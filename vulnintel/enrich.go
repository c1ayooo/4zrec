package vulnintel

// 情报富化链:对带 CVE 的情报做「怎么打(PoC)/ 影响谁(affected)/ 影响面
// (CVSS/EPSS/KEV)/ 可信度(triage 五档)」四维补全,写回 vuln_intel。
// 移植自老 4zreco manager_enrich.go + enrich.go + github.go + triage_pipe.go,
// 裁剪:磁盘缓存层(只留内存)、仓库深体检(README/文件树,只用搜索元数据
// 跑 triage)、GHSA 单公告兜底路径。语义保留:搜索失败不写 enriched_at 留待
// 重试;全部只补缺不覆盖。
//
// 凭据:GitHub 搜索需要 token(settings: vulnintel.github_token,普通 PAT 无
// scope 要求);无 token 时跳过 PoC 搜索,EPSS/KEV/NVD 照常(匿名)。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/vulnintel/triage"
)

const (
	enrichTimeout    = 45 * time.Second
	enrichBatchSize  = 20
	searchMinGap     = 2200 * time.Millisecond // GitHub Search 30/min 配额留余量
	httpTimeoutShort = 15 * time.Second
)

// githubTokenSettingsKey / nvdKeySettingsKey 配置键。
const (
	githubTokenSetting = "vulnintel.github_token"
	nvdKeyEnv          = "NVD_API_KEY"
)

// enricher 持有全部富化客户端(带内存缓存)与限流闸。
type enricher struct {
	pg  *db.DB
	hc  *http.Client
	tok func() string

	searchMu    sync.Mutex
	lastSearch  time.Time
	epssMu      sync.Mutex
	epssCache   map[string]epssEntry
	epssCacheAt time.Time
	kevMu       sync.Mutex
	kevSet      map[string]bool
	kevAt       time.Time
	nvdMu       sync.Mutex
	nvdCache    map[string]nvdMeta
}

type epssEntry struct {
	Score      float64
	Percentile float64
}

type nvdMeta struct {
	Vector      string
	Score       float64
	CWEs        []int
	Description string
	fetchedAt   time.Time
}

func newEnricher(pg *db.DB) *enricher {
	return &enricher{
		pg:       pg,
		hc:       &http.Client{Timeout: httpTimeoutShort},
		epssCache: map[string]epssEntry{},
		nvdCache: map[string]nvdMeta{},
	}
}

// httpGetJSON 是统一出站:UA + 限量读体。
func (e *enricher) httpGetJSON(ctx context.Context, url string, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "4zrec-vulnintel/1.0")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %s: %s", resp.Status, string(body))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// ---- EPSS(api.first.org,批量,匿名) ----

func (e *enricher) getEPSS(ctx context.Context, cves []string) map[string]epssEntry {
	e.epssMu.Lock()
	if time.Since(e.epssCacheAt) > 24*time.Hour {
		e.epssCache = map[string]epssEntry{}
		e.epssCacheAt = time.Now()
	}
	cache := e.epssCache
	e.epssMu.Unlock()

	out := map[string]epssEntry{}
	var miss []string
	for _, c := range cves {
		if v, ok := cache[c]; ok {
			out[c] = v
		} else {
			miss = append(miss, c)
		}
	}
	for i := 0; i < len(miss); i += 100 {
		end := i + 100
		if end > len(miss) {
			end = len(miss)
		}
		batch := miss[i:end]
		var resp struct {
			Data []struct {
				CVE        string `json:"cve"`
				Epss       string `json:"epss"`
				Percentile string `json:"percentile"`
			} `json:"data"`
		}
		q := strings.Join(batch, ",")
		if err := e.httpGetJSON(ctx, "https://api.first.org/data/v1/epss?cve="+q, "", &resp); err != nil {
			continue // 单批失败降级:该批 EPSS 缺失
		}
		for _, d := range resp.Data {
			var en epssEntry
			fmt.Sscanf(d.Epss, "%f", &en.Score)
			fmt.Sscanf(d.Percentile, "%f", &en.Percentile)
			out[d.CVE] = en
			e.epssMu.Lock()
			e.epssCache[d.CVE] = en
			e.epssMu.Unlock()
		}
	}
	return out
}

// ---- KEV(CISA 全量 feed,匿名,24h 缓存) ----

func (e *enricher) inKEV(ctx context.Context, cve string) bool {
	e.kevMu.Lock()
	if e.kevSet == nil || time.Since(e.kevAt) > 24*time.Hour {
		e.kevMu.Unlock()
		var feed struct {
			Vulnerabilities []struct {
				CVEID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if err := e.httpGetJSON(ctx, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "", &feed); err == nil {
			set := make(map[string]bool, len(feed.Vulnerabilities))
			for _, v := range feed.Vulnerabilities {
				set[v.CVEID] = true
			}
			e.kevMu.Lock()
			e.kevSet = set
			e.kevAt = time.Now()
			e.kevMu.Unlock()
		} else {
			return false
		}
	} else {
		e.kevMu.Unlock()
	}
	e.kevMu.Lock()
	defer e.kevMu.Unlock()
	return e.kevSet[cve]
}

// ---- NVD(单查,可选 key) ----

func (e *enricher) getNVD(ctx context.Context, cve string) (nvdMeta, bool) {
	e.nvdMu.Lock()
	if time.Since(e.nvdCache[cve].fetchedAt) < 6*time.Hour {
		m := e.nvdCache[cve]
		e.nvdMu.Unlock()
		return m, m.fetchedAt != time.Time{}
	}
	e.nvdMu.Unlock()

	var resp struct {
		Vulnerabilities []struct {
			CVE struct {
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							VectorString string  `json:"vectorString"`
							BaseScore    float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV2 []struct {
						CvssData struct {
							VectorString string  `json:"vectorString"`
							BaseScore    float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := e.httpGetJSON(ctx, "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="+cve, "", &resp); err != nil {
		return nvdMeta{}, false
	}
	var m nvdMeta
	if len(resp.Vulnerabilities) == 0 {
		e.nvdMu.Lock()
		e.nvdCache[cve] = nvdMeta{fetchedAt: time.Now()} // 空结果也缓存防反复打
		e.nvdMu.Unlock()
		return nvdMeta{}, false
	}
	c := resp.Vulnerabilities[0].CVE
	if len(c.Metrics.CvssMetricV31) > 0 {
		m.Vector = c.Metrics.CvssMetricV31[0].CvssData.VectorString
		m.Score = c.Metrics.CvssMetricV31[0].CvssData.BaseScore
	} else if len(c.Metrics.CvssMetricV2) > 0 {
		m.Vector = c.Metrics.CvssMetricV2[0].CvssData.VectorString
		m.Score = c.Metrics.CvssMetricV2[0].CvssData.BaseScore
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			var n int
			if strings.HasPrefix(d.Value, "CWE-") {
				fmt.Sscanf(d.Value, "CWE-%d", &n)
				if n > 0 {
					m.CWEs = append(m.CWEs, n)
				}
			}
		}
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			m.Description = d.Value
			break
		}
	}
	e.nvdMu.Lock()
	m.fetchedAt = time.Now()
	e.nvdCache[cve] = m
	e.nvdMu.Unlock()
	return m, true
}

// ---- GitHub(PoC 仓库搜索 + GHSA Advisory;需要 token) ----

type ghRepo struct {
	FullName    string `json:"full_name"`
	HTMLURL     string `json:"html_url"`
	Description string `json:"description"`
	Stars       int    `json:"stargazers_count"`
	Forks       int    `json:"forks_count"`
	CreatedAt   string `json:"created_at"`
	PushedAt    string `json:"pushed_at"`
	IsFork      bool   `json:"fork"`
	Archived    bool   `json:"archived"`
}

// searchPOC 仓库搜索;串行 + 最小间隔(账号级 30/min 配额保护)。
func (e *enricher) searchPOC(ctx context.Context, cve string) ([]ghRepo, error) {
	token := ""
	if e.tok != nil {
		token = strings.TrimSpace(e.tok())
	}
	if token == "" {
		return nil, nil // 无 token:跳过,不算失败(不阻断 enriched_at)
	}
	e.searchMu.Lock()
	if gap := searchMinGap - time.Since(e.lastSearch); gap > 0 {
		select {
		case <-time.After(gap):
		case <-ctx.Done():
			e.searchMu.Unlock()
			return nil, ctx.Err()
		}
	}
	e.lastSearch = time.Now()
	e.searchMu.Unlock()

	var resp struct {
		Items []ghRepo `json:"items"`
	}
	err := e.httpGetJSON(ctx,
		"https://api.github.com/search/repositories?q="+cve+"&sort=stars&order=desc&per_page=5", token, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Items, nil
}

type ghAdvisory struct {
	Summary string `json:"summary"`
	Severity string `json:"severity"`
	CVSS struct {
		VectorString string  `json:"vector_string"`
		Score        float64 `json:"score"`
	} `json:"cvss"`
	Cwes []struct {
		CWEID string `json:"cwe_id"`
	} `json:"cwes"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatched           struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched"`
	} `json:"vulnerabilities"`
}

func (e *enricher) fetchAdvisory(ctx context.Context, cve string) (*ghAdvisory, error) {
	token := ""
	if e.tok != nil {
		token = strings.TrimSpace(e.tok())
	}
	if token == "" {
		return nil, nil
	}
	var resp []ghAdvisory
	if err := e.httpGetJSON(ctx, "https://api.github.com/advisories?cve_id="+cve+"&per_page=1", token, &resp); err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, nil
	}
	return &resp[0], nil
}

// ---- 富化编排 ----

// enrichVuln 对一条情报执行完整富化并写回。搜索失败返回 error(调用方不把
// 该条标记完成,留待下轮);其余源失败降级继续。
func (e *enricher) enrichVuln(ctx context.Context, v db.VulnIntel) error {
	ctx, cancel := context.WithTimeout(ctx, enrichTimeout)
	defer cancel()

	cve := strings.TrimSpace(v.CVE)
	out := db.VulnIntelEnrich{ID: v.ID}

	// ① GitHub PoC 搜索 + triage 五档体检。
	repos, serr := e.searchPOC(ctx, cve)
	if serr != nil {
		return fmt.Errorf("poc search: %w", serr) // 不写 enriched_at,下轮重试
	}
	// ② EPSS/KEV/NVD 元数据。
	epss := e.getEPSS(ctx, []string{cve})[cve]
	inKEV := e.inKEV(ctx, cve)
	nvd, _ := e.getNVD(ctx, cve)
	adv, _ := e.fetchAdvisory(ctx, cve)

	// ③ 聚合 CVSS/CWE/affected(GHSA 优先,NVD 兜底)。
	cvssScore := nvd.Score
	cvssVector := nvd.Vector
	var cwes []int
	cwes = append(cwes, nvd.CWEs...)
	var affected []string
	supplementTitle := ""
	if adv != nil {
		if adv.CVSS.Score > 0 {
			cvssScore = adv.CVSS.Score
			cvssVector = adv.CVSS.VectorString
		}
		for _, c := range adv.Cwes {
			var n int
			fmt.Sscanf(c.CWEID, "CWE-%d", &n)
			if n > 0 {
				cwes = append(cwes, n)
			}
		}
		for _, av := range adv.Vulnerabilities {
			affected = append(affected, av.Package.Ecosystem+"/"+av.Package.Name)
		}
		if summary := strings.TrimSpace(adv.Summary); summary != "" && len(summary) >= 8 {
			supplementTitle = summary
		}
	}
	cwes = dedupeInts(cwes)

	// ④ PoC 逐仓库 triage。
	pocs := []db.VulnIntelPOC{}
	labOnly := false
	for _, r := range repos {
		meta := triage.CVEMeta{
			CVEID:         cve,
			CVSSVector:    cvssVector,
			CVSSScore:     cvssScore,
			CWE:           cwes,
			Description:   v.Description,
			InKEV:         &inKEV,
			EPSS:          &epss.Score,
			EPSSPercentile: &epss.Percentile,
		}
		isFork := r.IsFork
		archived := r.Archived
		repoMeta := triage.RepoMeta{
			FullName:    r.FullName,
			Description: r.Description,
			Stars:       r.Stars,
			Forks:       r.Forks,
			CreatedAt:   r.CreatedAt,
			PushedAt:    r.PushedAt,
			IsFork:      &isFork,
			Archived:    &archived,
		}
		verdict, score, reasons := triage.Triage(meta, repoMeta)
		switch verdict {
		case triage.VerdictMalicious:
			continue // 恶意仓库隔离,不落库
		case triage.VerdictNoise:
			continue
		case triage.VerdictLabOnly:
			labOnly = true
			continue
		}
		if len(reasons) > 3 {
			reasons = reasons[:3]
		}
		pocs = append(pocs, db.VulnIntelPOC{
			FullName:    r.FullName,
			URL:         r.HTMLURL,
			Description: r.Description,
			Stars:       r.Stars,
			PushedAt:    r.PushedAt,
			Verdict:     string(verdict),
			TriageScore: score,
			Reasons:     reasons,
		})
	}
	sort.SliceStable(pocs, func(i, j int) bool { return pocs[i].Stars > pocs[j].Stars })

	pocJSON, _ := json.Marshal(pocs)
	cwesJSON, _ := json.Marshal(cweStrings(cwes))
	affJSON, _ := json.Marshal(dedupeStrings(affected))
	out.GithubPoc = string(pocJSON)
	out.CvssScore = cvssScore
	out.CvssVector = cvssVector
	out.Cwes = string(cwesJSON)
	out.Affected = string(affJSON)
	out.LabOnly = labOnly
	out.HasLabOnly = true
	out.SupplementTitle = supplementTitle
	out.HasTitle = supplementTitle != ""
	out.Enriched = true
	return e.pg.EnrichVulnIntel(out)
}

// enrichPending 拉一批待富化条目逐条跑;单条失败跳过不阻断。
func (e *enricher) enrichPending() {
	pending, err := e.pg.PendingVulnIntel(enrichBatchSize)
	if err != nil || len(pending) == 0 {
		return
	}
	done, failed := 0, 0
	for _, v := range pending {
		ctx, cancel := context.WithTimeout(context.Background(), enrichTimeout)
		err := e.enrichVuln(ctx, v)
		cancel()
		if err != nil {
			failed++
			continue
		}
		done++
	}
	if done > 0 || failed > 0 {
	log.Printf("[vulnintel] 富化批次完成: 成功 %d, 失败 %d(失败条目下轮重试)", done, failed)
	}
}

func dedupeInts(in []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, n := range in {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func cweStrings(cwes []int) []string {
	out := make([]string, 0, len(cwes))
	for _, n := range cwes {
		out = append(out, fmt.Sprintf("CWE-%d", n))
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
