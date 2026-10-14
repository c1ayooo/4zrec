// Package vulnintel 是漏洞情报自动入库管线:9 个公开情报源定时轮询 →
// 严重度门槛分诊 → 按唯一键幂等入库 vuln_intel。移植自老 4zreco 的
// internal/vulnintel(grab 适配器原样保留,manager 裁剪掉通知/沙箱/订阅等
// 老项目耦合,只留「抓取→过滤→入库」主线)。
package vulnintel

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/vulnintel/grab"
)

// settings 键。enabled 关掉即停轮询(下次 tick 生效),interval 改动同样
// 下轮生效——热更新不必重启。
const (
	settingEnabled  = "vulnintel.enabled"
	settingInterval = "vulnintel.interval_minutes"
)

func defaultEnabled(pg *db.DB) bool {
	v, ok, err := pg.GetSetting(settingEnabled)
	if err != nil || !ok {
		return true // 默认开启:全部源匿名公开端点,无凭据成本
	}
	return v == "1" || v == "true"
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

// Manager 持有全部抓取器并驱动轮询与富化。
type Manager struct {
	pg        *db.DB
	grabbers  []grab.Grabber
	refreshCh chan struct{}
	enr       *enricher
	mu        sync.Mutex
	lastPoll  time.Time
	lastRes   PollResult
	polling   bool
}

// NewManager 装配全部 9 源。
func NewManager(pg *db.DB) *Manager {
	m := &Manager{
		pg: pg,
		grabbers: []grab.Grabber{
			grab.NewAVDCrawler(),       // 阿里云漏洞库
			grab.NewChaitinCrawler(),   // 长亭漏洞库
			grab.NewTiCrawler(),        // 奇安信 TI
			grab.NewOSCSCrawler(),      // OSCS
			grab.NewThreatBookCrawler(), // 微步
			grab.NewSeebugCrawler(),    // Seebug
			grab.NewKEVCrawler(),       // CISA KEV
			grab.NewStruts2Crawler(),   // Apache S2 公告
			grab.NewVenustechCrawler(), // 启明星辰
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
			n, u := m.ingest(g, infos)
			mu.Lock()
			res.New += n
			res.Updated += u
			mu.Unlock()
		}(g)
	}
	wg.Wait()
	m.mu.Lock()
	m.lastRes = res
	m.mu.Unlock()
	log.Printf("[vulnintel] 轮询完成: 新增 %d, 更新 %d, 源失败 %d/%d, 耗时 %s",
		res.New, res.Updated, res.Failed, res.Sources, time.Since(start).Round(time.Second))
}

// ingest 过滤并入库一个源的批次。
func (m *Manager) ingest(g grab.Grabber, infos []*grab.VulnInfo) (newN, updatedN int) {
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
		} else {
			updatedN++
		}
	}
	return newN, updatedN
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
