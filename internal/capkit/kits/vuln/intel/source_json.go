package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ---- 长亭 (stack.chaitin.com) ----

// chaitinListURL returns one page of the CT- numbered advisory feed. The
// upstream caps limit at 15.
//
// The feed is fetched one page per poll on purpose. Paging through it trips the
// site's WAF after about four rapid requests and every later page answers 465
// with an HTML challenge instead of JSON (verified live, 2026-10-20) — so a
// paging loop does not fetch more advisories, it just converts a working source
// into a failing one. The feed is newest-first, and polling is periodic, so one
// page keeps the corpus current.
const chaitinListURL = "https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=0&search=CT-"

type chaitinSource struct{ c *client }

func newChaitinSource(c *client) Source { return &chaitinSource{c: c} }

func (s *chaitinSource) Info() Info {
	return Info{
		Name:        "chaitin",
		DisplayName: "长亭漏洞库",
		Link:        "https://stack.chaitin.com/vuldb/index",
	}
}

func (s *chaitinSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	if limit <= 0 {
		limit = 15
	}
	headers := map[string]string{
		"Accept":  "application/json",
		"Referer": "https://stack.chaitin.com/vuldb/index",
		"Origin":  "https://stack.chaitin.com",
	}
	raw, err := s.c.get(ctx, chaitinListURL, headers)
	if err != nil {
		return nil, upstreamError("chaitin", err)
	}
	var resp chaitinResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, upstreamError("chaitin", err)
	}
	out := make([]core.IntelItem, 0, len(resp.Data.List))
	for _, d := range resp.Data.List {
		if strings.TrimSpace(d.CtID) == "" {
			continue
		}
		var refs []string
		if d.References != nil {
			for _, ref := range strings.Split(*d.References, "\n") {
				if ref = strings.TrimSpace(ref); ref != "" {
					refs = append(refs, ref)
				}
			}
		}
		out = append(out, core.IntelItem{
			Source:      s.Info().Name,
			UniqueKey:   uniqueKey(d.CtID, "chaitin"),
			Title:       strings.TrimSpace(d.Title),
			Description: strings.TrimSpace(d.Summary),
			Severity:    NormalizeSeverity(d.Severity),
			CVE:         trimPtr(d.CveID),
			Disclosure:  dayOnly(d.CreatedAt),
			SourceURL:   "https://stack.chaitin.com/vuldb/detail/" + d.ID,
			References:  refs,
		})
	}
	return capItems(out, limit), nil
}

type chaitinResponse struct {
	Data struct {
		List []struct {
			ID         string    `json:"id"`
			Title      string    `json:"title"`
			Summary    string    `json:"summary"`
			Severity   string    `json:"severity"`
			CtID       string    `json:"ct_id"`
			CveID      *string   `json:"cve_id"`
			References *string   `json:"references"`
			CreatedAt  time.Time `json:"created_at"`
		} `json:"list"`
	} `json:"data"`
	Code int `json:"code"`
}

// ---- 奇安信威胁情报中心 (ti.qianxin.com) ----

// qianxinOneDayURL returns today's advisory delta. It carries several lists:
// vuln_add / vuln_update / key_vuln_add / poc_exp_add / patch_add. vuln_add is
// the full new-advisory list; key_vuln_add is the handful the vendor chose to
// highlight, so keying off only that one loses most of the day's advisories
// (76 vs 1 on a verified live call).
const qianxinOneDayURL = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day"

// qianxinOKStatus is this API's success code. It is 10000, not 0 or 200: the
// envelope is `{"status":10000,"message":"success"}`. Reading it as an error
// rejected a perfectly good response.
const qianxinOKStatus = 10000

type qianxinSource struct{ c *client }

func newQianxinSource(c *client) Source { return &qianxinSource{c: c} }

func (s *qianxinSource) Info() Info {
	return Info{
		Name:        "qianxin-ti",
		DisplayName: "奇安信威胁情报中心",
		Link:        "https://ti.qianxin.com/",
	}
}

func (s *qianxinSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	raw, err := s.c.postJSON(ctx, qianxinOneDayURL, map[string]string{
		"Accept":  "application/json",
		"Referer": "https://ti.qianxin.com/",
	}, map[string]any{})
	if err != nil {
		return nil, upstreamError("qianxin-ti", err)
	}
	var resp qianxinResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, upstreamError("qianxin-ti", err)
	}
	if resp.Status != qianxinOKStatus {
		return nil, upstreamError("qianxin-ti",
			fmt.Errorf("上游返回 status=%d message=%s", resp.Status, resp.Message))
	}
	out := make([]core.IntelItem, 0, len(resp.Data.VulnAdd))
	for _, d := range append(resp.Data.VulnAdd, resp.Data.KeyVulnAdd...) {
		if strings.TrimSpace(d.QvdCode) == "" {
			continue
		}
		var tags []string
		for _, tag := range d.Tag {
			if t := strings.TrimSpace(tag.Name); t != "" {
				tags = append(tags, t)
			}
		}
		for _, category := range strings.Split(d.ThreatCategory, ",") {
			if c := strings.TrimSpace(category); c != "" {
				tags = append(tags, c)
			}
		}
		if d.PocFlag != 0 {
			tags = append(tags, "有Poc")
		}
		if d.PatchFlag != 0 {
			tags = append(tags, "有补丁")
		}
		out = append(out, core.IntelItem{
			Source:      s.Info().Name,
			UniqueKey:   uniqueKey(d.QvdCode, "qianxin-ti"),
			Title:       strings.TrimSpace(d.VulnName),
			Description: strings.TrimSpace(d.Description),
			Severity:    NormalizeSeverity(d.RatingLevel),
			CVE:         strings.TrimSpace(d.CveCode),
			Disclosure:  strings.TrimSpace(d.PublishTime),
			SourceURL:   "https://ti.qianxin.com/vulnerability/detail/" + strconv.Itoa(d.ID),
			Tags:        dedupeStrings(tags),
		})
	}
	return capItems(dedupeByKey(out), limit), nil
}

type qianxinResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Data    struct {
		VulnAdd    []qianxinVuln `json:"vuln_add"`
		KeyVulnAdd []qianxinVuln `json:"key_vuln_add"`
	} `json:"data"`
}

// qianxinVuln is one advisory in either list; both lists carry the same shape.
type qianxinVuln struct {
	ID             int    `json:"id"`
	VulnName       string `json:"vuln_name"`
	QvdCode        string `json:"qvd_code"`
	CveCode        string `json:"cve_code"`
	PublishTime    string `json:"publish_time"`
	Description    string `json:"description"`
	RatingLevel    string `json:"rating_level"`
	ThreatCategory string `json:"threat_category"`
	// These are 0/1 integers upstream, not JSON booleans.
	PocFlag   int `json:"poc_flag"`
	PatchFlag int `json:"patch_flag"`
	Tag       []struct {
		Name string `json:"name"`
	} `json:"tag"`
}

// ---- 微步在线 (x.threatbook.com) ----

const threatbookHomeURL = "https://x.threatbook.com/v5/node/vul_module/homePage"

type threatbookSource struct{ c *client }

func newThreatBookSource(c *client) Source { return &threatbookSource{c: c} }

func (s *threatbookSource) Info() Info {
	return Info{
		Name:        "threatbook",
		DisplayName: "微步在线研究响应中心",
		Link:        "https://x.threatbook.com/v5/vulIntelligence",
	}
}

func (s *threatbookSource) Fetch(ctx context.Context, limit int) ([]core.IntelItem, error) {
	raw, err := s.c.get(ctx, threatbookHomeURL, map[string]string{
		"Accept":  "application/json",
		"Referer": "https://x.threatbook.com/v5/vulIntelligence",
	})
	if err != nil {
		return nil, upstreamError("threatbook", err)
	}
	var resp threatbookResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, upstreamError("threatbook", err)
	}
	out := make([]core.IntelItem, 0, len(resp.Data.HighRisk))
	for _, v := range resp.Data.HighRisk {
		if strings.TrimSpace(v.ID) == "" {
			continue
		}
		var tags []string
		if v.Is0Day {
			tags = append(tags, "0day")
		}
		if v.PocExist {
			tags = append(tags, "有Poc")
		}
		if v.Premium {
			tags = append(tags, "有漏洞分析")
		}
		if v.Solution {
			tags = append(tags, "有修复方案")
		}
		disclosure := firstNonEmpty(v.VulnPublishTime, v.VulnUpdateTime)
		out = append(out, core.IntelItem{
			Source:    s.Info().Name,
			UniqueKey: uniqueKey(v.ID, "threatbook"),
			Title:     strings.TrimSpace(v.VulnNameZh),
			// The homepage payload carries no description; the advisory body
			// lives behind the detail page, which this source does not fetch.
			Severity:   NormalizeSeverity(v.RiskLevel),
			Disclosure: disclosure,
			SourceURL:  "https://x.threatbook.com/v5/vul/" + v.ID,
			Tags:       tags,
		})
	}
	return capItems(out, limit), nil
}

type threatbookResponse struct {
	Data struct {
		HighRisk []struct {
			ID              string `json:"id"`
			VulnNameZh      string `json:"vuln_name_zh"`
			VulnUpdateTime  string `json:"vuln_update_time"`
			VulnPublishTime string `json:"vuln_publish_time"`
			PocExist        bool   `json:"pocExist"`
			Solution        bool   `json:"solution"`
			Premium         bool   `json:"premium"`
			RiskLevel       string `json:"riskLevel"`
			Is0Day          bool   `json:"is0day"`
		} `json:"highrisk"`
	} `json:"data"`
	ResponseCode int `json:"response_code"`
}
