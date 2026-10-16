package enterprise

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Collector BFS 编排器：深度/节点/速率硬限制 + 取消 + 进度落库。
// 投资与分支关系默认只作为候选情报，域名进入 candidate 资产，
// 不自动等同授权范围（导入需用户确认，见 handler assets/import）。
type Collector struct {
	store       *Store
	log         *log.Logger
	mu          sync.Mutex
	running     map[string]*runningJob // jobID -> 控制
	rateLimit   time.Duration          // 上游请求间隔
	pageSize    int
	maxPageWalk int // 每个企业翻页上限
	scanner     FingerprintScanner
}

type runningJob struct {
	cancel context.CancelFunc
}

func (c *Collector) SetFingerprintScanner(scanner FingerprintScanner) { c.scanner = scanner }

func NewCollector(store *Store, lg *log.Logger) *Collector {
	if lg == nil {
		lg = log.Default()
	}
	return &Collector{store: store, log: lg, running: map[string]*runningJob{}, rateLimit: 800 * time.Millisecond, pageSize: 10, maxPageWalk: 5}
}

// Start 启动后台 BFS 采集任务，立即返回 job（status=running）。
func (c *Collector) Start(ctx context.Context, provider Provider, job Job, root CompanyRef) (Job, error) {
	if job.Depth < 1 {
		job.Depth = 1
	}
	if job.Depth > 3 {
		job.Depth = 3
	}
	if job.MaxNodes < 1 {
		job.MaxNodes = 20
	}
	if job.MaxNodes > c.store.maxNodes {
		job.MaxNodes = c.store.maxNodes
	}
	created, err := c.store.CreateJob(ctx, job)
	if err != nil {
		return Job{}, err
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c.mu.Lock()
	c.running[created.ID] = &runningJob{cancel: cancel}
	c.mu.Unlock()
	go c.run(runCtx, provider, created, root)
	return created, nil
}

// Cancel 取消运行中的任务。
func (c *Collector) Cancel(jobID string) bool {
	c.mu.Lock()
	rj, ok := c.running[jobID]
	c.mu.Unlock()
	if !ok {
		return false
	}
	rj.cancel()
	return true
}

func (c *Collector) forget(jobID string) {
	c.mu.Lock()
	delete(c.running, jobID)
	c.mu.Unlock()
}

func (c *Collector) run(ctx context.Context, provider Provider, job Job, root CompanyRef) {
	defer c.forget(job.ID)
	status, msg := "waiting_authorization", ""
	targets, walkErr := c.walk(ctx, provider, job, root)
	if walkErr != nil {
		if ctx.Err() != nil {
			status, msg = "canceled", "用户取消"
		} else {
			status, msg = "error", walkErr.Error()
		}
	}
	if status == "waiting_authorization" {
		_ = c.store.SetFingerprintStatus(context.Background(), job.ID, "waiting_authorization", "", FingerprintStats{Total: len(targets)})
	}
	if err := c.store.FinishJob(context.Background(), job.ID, status, msg); err != nil {
		c.log.Printf("[enterprise] 任务 %s 状态落库失败: %v", job.ID, err)
	}
}

// walk 从根企业开始逐层展开：detail → 域名入候选 → 子公司(分支/投资)入队。
func (c *Collector) walk(ctx context.Context, provider Provider, job Job, root CompanyRef) ([]string, error) {
	type item struct {
		ref        CompanyRef
		depth      int
		entityType string
		parentID   string
	}
	queue := []item{{ref: root, depth: 0, entityType: "root"}}
	visited := map[string]bool{root.ExtID: true}
	nodes := 0
	targets := make([]string, 0)
	targetSeen := map[string]bool{}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return targets, err
		}
		if nodes >= job.MaxNodes {
			return targets, fmt.Errorf("达到节点上限 %d，任务中止（可调大 max_nodes 后重试）", job.MaxNodes)
		}
		cur := queue[0]
		queue = queue[1:]

		detail, err := provider.Detail(ctx, cur.ref.ExtID)
		if err != nil {
			return targets, fmt.Errorf("获取企业详情失败(%s): %w", cur.ref.Name, err)
		}
		if err := c.pace(ctx); err != nil {
			return targets, err
		}
		nodes++
		name := cur.ref.Name
		if detail != nil && detail.Name != "" {
			name = detail.Name
		}
		e := &Entity{JobID: job.ID, ExtID: cur.ref.ExtID, Name: name, EntityType: cur.entityType,
			ParentExtID: cur.parentID, Depth: cur.depth}
		if detail != nil {
			e.LegalPerson, e.OpenStatus, e.Phone, e.Email = detail.LegalPerson, detail.OpenStatus, detail.Phone, detail.Email
		}
		inserted, err := c.store.SaveEntity(ctx, e)
		if err != nil {
			return targets, fmt.Errorf("保存企业实体失败: %w", err)
		}
		entities := 0
		domains := 0
		if inserted {
			entities = 1
		}
		if detail != nil {
			for _, d := range detail.Domains {
				if ok, err := c.store.SaveDomain(ctx, job.ID, d.Domain, d.Site, d.ICP, name); err == nil && ok {
					domains++
				}
				if normalized := normalizeDomain(d.Domain); normalized != "" && !targetSeen[normalized] {
					targetSeen[normalized] = true
					targets = append(targets, normalized)
				}
			}
		}
		// 关联域名/备案：翻页受 maxPageWalk 限制
		for page := 1; page <= c.maxPageWalk; page++ {
			if err := c.pace(ctx); err != nil {
				return targets, err
			}
			hits, more, err := provider.Domains(ctx, cur.ref.ExtID, page, c.pageSize)
			if err != nil {
				c.log.Printf("[enterprise] 域名列表失败(%s): %v", cur.ref.ExtID, err)
				break
			}
			for _, d := range hits {
				if ok, err := c.store.SaveDomain(ctx, job.ID, d.Domain, d.Site, d.ICP, name); err == nil && ok {
					domains++
				}
				if normalized := normalizeDomain(d.Domain); normalized != "" && !targetSeen[normalized] {
					targetSeen[normalized] = true
					targets = append(targets, normalized)
				}
			}
			if !more {
				break
			}
		}
		if err := c.store.BumpJob(ctx, job.ID, 1, entities, domains); err != nil {
			return targets, err
		}

		// 展开下一层：分支机构 + 对外投资
		if cur.depth < job.Depth {
			children, err := c.collectChildren(ctx, provider, cur.ref.ExtID)
			if err != nil {
				return targets, err
			}
			for _, ch := range children {
				if visited[ch.ExtID] {
					continue
				}
				visited[ch.ExtID] = true
				queue = append(queue, item{ref: ch.CompanyRef, depth: cur.depth + 1, entityType: ch.entType, parentID: cur.ref.ExtID})
			}
		}
	}
	return targets, nil
}

type childRef struct {
	CompanyRef
	entType string
}

// collectChildren 抓取分支+投资列表，翻页受 maxPageWalk 硬限制。
func (c *Collector) collectChildren(ctx context.Context, provider Provider, extID string) ([]childRef, error) {
	var out []childRef
	for _, spec := range []struct {
		typ  string
		list func(ctx context.Context, extID string, page, size int) ([]CompanyRef, bool, error)
	}{
		{"branch", provider.Branches},
		{"invest", provider.Investments},
	} {
		for page := 1; page <= c.maxPageWalk; page++ {
			if err := c.pace(ctx); err != nil {
				return nil, err
			}
			refs, more, err := spec.list(ctx, extID, page, c.pageSize)
			if err != nil {
				// 列表失败不致命：记录后继续其余类型
				c.log.Printf("[enterprise] %s 列表失败(%s): %v", spec.typ, extID, err)
				break
			}
			for _, r := range refs {
				if r.ExtID == "" {
					continue
				}
				out = append(out, childRef{CompanyRef: r, entType: spec.typ})
			}
			if !more {
				break
			}
		}
	}
	return out, nil
}

// pace 上游请求节流，尊重取消。
func (c *Collector) pace(ctx context.Context) error {
	if c.rateLimit <= 0 {
		return nil
	}
	t := time.NewTimer(c.rateLimit)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
