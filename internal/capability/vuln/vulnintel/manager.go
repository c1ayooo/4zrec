// Package vulnintel 是漏洞情报自动入库管线:9 个公开情报源定时轮询 →
// 严重度门槛分诊 → 按唯一键幂等入库 vuln_intel → 富化(EPSS/KEV/NVD/GitHub PoC)
// → AI 分析流水线(中文简介/原理/攻击范围/PoC → 中文化 → nuclei 模板化)。
// 抓取与富化移植自老 4zreco;分析流水线移植自 ai_bobao 的 analyzer/translate/
// nuclei_tpl 三段,落在 Postgres 与项目既有 nuclei 模板库上。
package vulnintel

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/vulnintel/grab"
	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// settings 键。enabled 关掉即停轮询(下次 tick 生效),interval 改动同样
// 下轮生效——热更新不必重启。分析流水线的四个开关同理,每轮重新读取。
const (
	settingEnabled  = "vulnintel.enabled"
	settingInterval = "vulnintel.interval_minutes"

	settingAnalyzeEnabled = "vulnintel.analyze_enabled"
	settingAutoTranslate  = "vulnintel.auto_translate"
	settingAutoNuclei     = "vulnintel.auto_nuclei"
	settingNotifyEnabled  = "vulnintel.notify_enabled"
)

const (
	analyzeBatchSize   = 5                // 每轮分析条数
	analyzeLoopEvery   = 10 * time.Minute // 分析轮询节拍
	analysisStartDelay = 90 * time.Second // 启动后首次分析延迟,避免重启即烧 token
)

func boolSetting(pg *db.DB, key string, def bool) bool {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	return v == "1" || v == "true"
}

func defaultEnabled(pg *db.DB) bool {
	return boolSetting(pg, settingEnabled, true) // 默认开启:全部源匿名公开端点,无凭据成本
}

func interval(pg *db.DB) time.Duration {
	v, _, _ := pg.GetSetting(settingInterval)
	var n int
	for _, c := range v {
		if c < '0' || c > '9' {
			n = 0
			break
		}
		n = n*10 + int(c-'0')
	}
	if n < 5 {
		n = 30
	}
	return time.Duration(n) * time.Minute
}

// severityRank 中危以下不值得进库(与老项目 intakeAllowed 同阈值)。
var severityRank = map[string]int{
	"低危": 1, "中危": 2, "高危": 3, "严重": 4,
	"low": 1, "medium": 2, "high": 3, "critical": 4,
}

func intakeAllowed(severity string) bool {
	return severityRank[severity] >= 2
}

// PollResult 汇总一次轮询。
type PollResult struct {
	New     int
	Updated int
	Sources int
	Failed  int
}

// PipelineStatus 是 AI 分析流水线的对外状态(设置页/情报页展示)。
type PipelineStatus struct {
	AnalyzeEnabled bool      `json:"analyze_enabled"`
	AutoTranslate  bool      `json:"auto_translate"`
	AutoNuclei     bool      `json:"auto_nuclei"`
	NotifyEnabled  bool      `json:"notify_enabled"`
	LLMReady       bool      `json:"llm_ready"`
	Running        bool      `json:"running"`
	LastRun        time.Time `json:"last_run"`
	LastDone       int       `json:"last_done"`
	LastFailed     int       `json:"last_failed"`
	Pending        int       `json:"pending"`
	Analyzed       int       `json:"analyzed"`
}

// Manager 持有全部抓取器并驱动轮询、富化与分析流水线。
type Manager struct {
	pg       *db.DB
	grabbers []grab.Grabber
	refreshCh chan struct{}
	enr      *enricher
	mu       sync.Mutex
	lastPoll time.Time
	lastRes  PollResult
	polling  bool

	// 分析流水线。三个钩子由宿主(server 层)注入,能力包不感知 LLM 提供方、
	// nuclei 管理器与 IM 通知实现——沿用 server Manager 的 taskStatusHook 范式。
	llm      LLM
	tplSink  TemplateSink
	notifyFn func(newHigh int, titles []string)

	pipelineRunning  bool
	lastPipeline     time.Time
	lastPipelineDone int
	lastPipelineFail int
}

// NewManager 装配全部 9 源。
func NewManager(pg *db.DB) *Manager {
	m := &Manager{
		pg: pg,
		grabbers: []grab.Grabber{
			grab.NewAVDCrawler(),        // 阿里云漏洞库
			grab.NewChaitinCrawler(),    // 长亭漏洞库
			grab.NewTiCrawler(),         // 奇安信 TI
			grab.NewOSCSCrawler(),       // OSCS
			grab.NewThreatBookCrawler(), // 微步
			grab.NewSeebugCrawler(),     // Seebug
			grab.NewKEVCrawler(),        // CISA KEV
			grab.NewStruts2Crawler(),    // Apache S2 公告
			grab.NewVenustechCrawler(),  // 启明星辰
		},
		refreshCh: make(chan struct{}, 1),
	}
	m.enr = newEnricher(pg)
	m.enr.SetTokenProvider(func() string {
		v, _, _ := pg.GetSetting(githubTokenSetting)
		return v
	})
	return m
}

// SetLLM 注入 LLM 补全能力(分析/中文化/模板指标都用它)。nil Complete 时整条
// 分析流水线静默跳过。
func (m *Manager) SetLLM(llm LLM) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.llm = llm
}

// SetTemplateSink 注入 nuclei 模板落盘实现。
func (m *Manager) SetTemplateSink(fn TemplateSink) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tplSink = fn
}

// SetNotifyHook 注入「新增高危情报」回调(由宿主转成 IM 通知)。
func (m *Manager) SetNotifyHook(fn func(newHigh int, titles []string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifyFn = fn
}

func (m *Manager) notifyHook() func(int, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.notifyFn
}

// ---- 分析流水线开关(每轮重新读取,切换即时生效) ----

func (m *Manager) analyzeEnabled() bool { return boolSetting(m.pg, settingAnalyzeEnabled, true) }
func (m *Manager) autoTranslate() bool  { return boolSetting(m.pg, settingAutoTranslate, true) }
func (m *Manager) autoNuclei() bool     { return boolSetting(m.pg, settingAutoNuclei, false) }
func (m *Manager) notifyEnabled() bool  { return boolSetting(m.pg, settingNotifyEnabled, true) }

// Start 启动轮询循环:立即跑一轮,此后按间隔;refresh 通道随时插队。
func (m *Manager) Start() {
	go func() {
		// 富化独立节拍(纯 timer,不消费 refreshCh——那是抓取循环的信号),
		// 消化积压(首轮几百条)与 7 天重富化。
		m.enr.enrichPending()
		for {
			time.Sleep(10 * time.Minute)
			m.enr.enrichPending()
		}
	}()
	go func() {
		// 分析流水线独立节拍:延迟首轮,避免每次重启都立刻烧一轮 token。
		time.Sleep(analysisStartDelay)
		for {
			m.runPipeline()
			time.Sleep(analyzeLoopEvery)
		}
	}()
	go func() {
		for {
			iv := interval(m.pg)
			if !defaultEnabled(m.pg) {
				iv = time.Minute // 关闭态降频空转,等重新开启
				select {
				case <-m.refreshCh:
				case <-time.After(iv):
				}
				continue
			}
			select {
			case <-m.refreshCh:
			case <-time.After(iv):
			}
			m.pollOnce()
		}
	}()
}

// Refresh 触发一次立即轮询(非阻塞;已在轮询中则忽略)。
func (m *Manager) Refresh() {
	select {
	case m.refreshCh <- struct{}{}:
	default:
	}
}

// Status 返回当前状态(前端展示)。
func (m *Manager) Status() (polling bool, lastPoll time.Time, lastRes PollResult, sources int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.polling, m.lastPoll, m.lastRes, len(m.grabbers)
}

// PipelineStatus 返回分析流水线的开关、进度与积压。
func (m *Manager) PipelineStatus() PipelineStatus {
	m.mu.Lock()
	st := PipelineStatus{
		Running:    m.pipelineRunning,
		LastRun:    m.lastPipeline,
		LastDone:   m.lastPipelineDone,
		LastFailed: m.lastPipelineFail,
		LLMReady:   m.llm.Complete != nil,
	}
	m.mu.Unlock()
	st.AnalyzeEnabled = m.analyzeEnabled()
	st.AutoTranslate = m.autoTranslate()
	st.AutoNuclei = m.autoNuclei()
	st.NotifyEnabled = m.notifyEnabled()
	if n, err := m.pg.IntelAnalysisPendingCount(); err == nil {
		st.Pending = n
	}
	if n, err := m.pg.IntelAnalyzedCount(); err == nil {
		st.Analyzed = n
	}
	return st
}

// AnalyzeIntel 立即对单条情报跑完整分析链(分析 → 中文化 → 可选模板化)。
// 供详情页「AI 分析」按钮与人工重试使用。
func (m *Manager) AnalyzeIntel(ctx context.Context, id int64) error {
	v, err := m.pg.GetVulnIntel(id)
	if err != nil {
		return err
	}
	if err := m.analyzeOne(ctx, *v); err != nil {
		_ = m.pg.SetIntelAnalysisError(id, err.Error())
		return err
	}
	return nil
}

// runPipeline 是分析流水线的节拍:拉一批待分析情报逐条处理。
func (m *Manager) runPipeline() {
	if !m.analyzeEnabled() && !m.autoTranslate() {
		return
	}
	if m.llmConfig().Complete == nil {
		return // 没接 LLM:不跑,也不留失败标记
	}
	m.mu.Lock()
	if m.pipelineRunning {
		m.mu.Unlock()
		return
	}
	m.pipelineRunning = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.pipelineRunning = false
		m.lastPipeline = time.Now()
		m.mu.Unlock()
	}()

	pending, err := m.pg.PendingIntelAnalysis(analyzeBatchSize)
	if err != nil || len(pending) == 0 {
		return
	}
	done, failed := 0, 0
	for _, v := range pending {
		ctx, cancel := context.WithTimeout(context.Background(), analysisTimeout+localizeTimeout)
		var perr error
		if m.analyzeEnabled() {
			perr = m.analyzeOne(ctx, v)
		} else {
			perr = m.localizeItem(ctx, v)
		}
		cancel()
		if perr != nil {
			failed++
			if setErr := m.pg.SetIntelAnalysisError(v.ID, perr.Error()); setErr != nil {
				log.Printf("[vulnintel] 记录分析失败原因 %d: %v", v.ID, setErr)
			}
			continue
		}
		done++
	}
	m.mu.Lock()
	m.lastPipelineDone = done
	m.lastPipelineFail = failed
	m.mu.Unlock()
	log.Printf("[vulnintel] 分析批次完成: 成功 %d, 失败 %d(失败条目下轮重试)", done, failed)
}

// pollOnce 并发跑全部源。单源失败只计数不中断(公开端点偶发 5xx/WAF 挑战
// 失败是常态,下一轮自然重试)。
func (m *Manager) pollOnce() {
	m.mu.Lock()
	if m.polling {
		m.mu.Unlock()
		return
	}
	m.polling = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.polling = false
		m.lastPoll = time.Now()
		m.mu.Unlock()
	}()

	start := time.Now()
	res := PollResult{Sources: len(m.grabbers)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var newHigh []string
	for _, g := range m.grabbers {
		wg.Add(1)
		go func(g grab.Grabber) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			infos, err := g.GetUpdate(ctx, 3)
			if err != nil {
				log.Printf("[vulnintel] %s: %v", g.ProviderInfo().Name, err)
				mu.Lock()
				res.Failed++
				mu.Unlock()
				return
			}
			n, u, high := m.ingest(g, infos)
			mu.Lock()
			res.New += n
			res.Updated += u
			newHigh = append(newHigh, high...)
			mu.Unlock()
		}(g)
	}
	wg.Wait()
	m.mu.Lock()
	m.lastRes = res
	m.mu.Unlock()
	log.Printf("[vulnintel] 轮询完成: 新增 %d, 更新 %d, 源失败 %d/%d, 耗时 %s",
		res.New, res.Updated, res.Failed, res.Sources, time.Since(start).Round(time.Second))

	// 本轮新增的高危/严重情报即时推一条 IM 汇总(开关可关)。
	if len(newHigh) > 0 && m.notifyEnabled() {
		if fn := m.notifyHook(); fn != nil {
			fn(len(newHigh), newHigh)
		}
	}
}

// ingest 过滤并入库一个源的批次。第三个返回值是本批新增的 高危/严重 情报标题。
func (m *Manager) ingest(g grab.Grabber, infos []*grab.VulnInfo) (newN, updatedN int, newHigh []string) {
	for _, info := range infos {
		if !intakeAllowed(string(info.Severity)) {
			continue
		}
		tags, _ := json.Marshal(info.Tags)
		refs, _ := json.Marshal(info.References)
		url := ""
		if len(info.References) > 0 {
			url = info.References[0]
		}
		inserted, err := m.pg.UpsertVulnIntel(db.VulnIntel{
			UniqueKey:   info.UniqueKey,
			Title:       info.Title,
			Description: truncateRunes(info.Description, 2000),
			Severity:    string(info.Severity),
			CVE:         info.CVE,
			Disclosure:  info.Disclosure,
			Solutions:   truncateRunes(info.Solutions, 2000),
			Source:      g.ProviderInfo().DisplayName,
			SourceURL:   url,
			Tags:        string(tags),
			Refs:        string(refs),
		})
		if err != nil {
			log.Printf("[vulnintel] upsert %s: %v", info.UniqueKey, err)
			continue
		}
		if inserted {
			newN++
			if rank := severityRank[string(info.Severity)]; rank >= 3 {
				newHigh = append(newHigh, info.Title)
			}
		} else {
			updatedN++
		}
	}
	return newN, updatedN, newHigh
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
