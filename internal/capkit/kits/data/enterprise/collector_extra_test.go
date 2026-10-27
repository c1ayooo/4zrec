package enterprise

import (
	"context"
	"errors"
	"testing"
	"time"
)

// failFinishStore 让 FinishJob 失败，用于覆盖 run 的落库失败分支。
type failFinishStore struct{ fakeStore }

func (s *failFinishStore) FinishJob(context.Context, string, string, string) error {
	return errors.New("finish db down")
}

func TestCollectorClamps(t *testing.T) {
	st := &fakeStore{}
	c := NewCollector(st, 100, nil)
	c.rateLimit = 0

	t.Run("Depth 超上限被压到 3", func(t *testing.T) {
		job, err := c.Start(context.Background(), &detailProvider{name: "p"}, Job{Depth: 9, MaxNodes: 5}, CompanyRef{ExtID: "r"})
		if err != nil {
			t.Fatal(err)
		}
		if job.Depth != 3 {
			t.Fatalf("Depth = %d, want 3", job.Depth)
		}
	})

	t.Run("MaxNodes<1 抬到 20", func(t *testing.T) {
		job, err := c.Start(context.Background(), &detailProvider{name: "p"}, Job{Depth: 1, MaxNodes: -5}, CompanyRef{ExtID: "r"})
		if err != nil {
			t.Fatal(err)
		}
		if job.MaxNodes != 20 {
			t.Fatalf("MaxNodes = %d, want 20", job.MaxNodes)
		}
	})
}

func TestCollectorWalkCancelledContext(t *testing.T) {
	st := &fakeStore{}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 0

	// Start 用 context.WithoutCancel，故直接调用 run 传入已取消的 ctx，
	// 确定性覆盖 walk 首轮 ctx.Err() 与 run 的 canceled 映射。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.mu.Lock()
	c.running["j"] = &runningJob{cancel: cancel}
	c.mu.Unlock()
	c.run(ctx, &detailProvider{name: "p"}, Job{ID: "j", Depth: 1, MaxNodes: 5}, CompanyRef{ExtID: "root"})

	_, finished, _, _, _ := st.snapshot()
	if len(finished) != 1 || finished[0].status != "canceled" {
		t.Fatalf("finished = %+v, want 单条 canceled", finished)
	}
}

func TestCollectorWalkPaceCancel(t *testing.T) {
	st := &fakeStore{}
	p := &detailProvider{
		name:     "p",
		branches: map[string][]CompanyRef{"root": {{ExtID: "b1", Name: "分公司"}}},
	}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 10 * time.Second

	job, err := c.Start(context.Background(), p, Job{Depth: 2, MaxNodes: 20}, CompanyRef{ExtID: "root"})
	if err != nil {
		t.Fatal(err)
	}
	// 等 walk 进入 pace 后取消，触发 collectChildren 的 ctx 错误路径。
	time.Sleep(50 * time.Millisecond)
	c.Cancel(job.ID)
	waitFinish(t, st, 1)
	_, finished, _, _, _ := st.snapshot()
	if finished[len(finished)-1].status != "canceled" {
		t.Fatalf("status = %q, want canceled", finished[len(finished)-1].status)
	}
}

func TestCollectorSkipsEmptyChildExtID(t *testing.T) {
	st := &fakeStore{insertAllow: true}
	p := &detailProvider{
		name: "p",
		// 分支含空 ExtID 条目，应被 collectChildren 跳过（不产生新实体）。
		branches: map[string][]CompanyRef{"root": {{ExtID: "", Name: "无ID"}, {ExtID: "b1", Name: "分公司"}}},
	}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 0
	if _, err := c.Start(context.Background(), p, Job{Depth: 1, MaxNodes: 20}, CompanyRef{ExtID: "root"}); err != nil {
		t.Fatal(err)
	}
	waitFinish(t, st, 1)
	_, _, entities, _, _ := st.snapshot()
	// root + b1 = 2；空 ExtID 子项被跳过（否则为 3）。
	if len(entities) != 2 {
		t.Fatalf("entities = %d, want 2（空 ExtID 子项应被跳过）", len(entities))
	}
}

func TestCollectorRunFinishJobFailure(t *testing.T) {
	st := &failFinishStore{}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 0
	if _, err := c.Start(context.Background(), &detailProvider{name: "p"}, Job{Depth: 1, MaxNodes: 5}, CompanyRef{ExtID: "root"}); err != nil {
		t.Fatal(err)
	}
	// FinishJob 失败只记日志，不 panic；任务仍应从 running 表移除。
	time.Sleep(50 * time.Millisecond)
	c.mu.Lock()
	_, stillRunning := c.running["job-1"]
	c.mu.Unlock()
	if stillRunning {
		t.Fatal("任务结束后 running 未清理")
	}
}

func TestCollectorPageWalkLimit(t *testing.T) {
	st := &fakeStore{insertAllow: true, domainAllow: true}
	p := &detailProvider{
		name:        "p",
		domainsMore: map[string]bool{"root": true},
		domains:     map[string][]DomainHit{"root": {{Domain: "a.com"}}},
		brMore:      map[string]bool{"root": true},
		branches:    map[string][]CompanyRef{"root": {{ExtID: "b1", Name: "分"}}},
		inMore:      map[string]bool{"root": true},
		invests:     map[string][]CompanyRef{"root": {{ExtID: "i1", Name: "投"}}},
	}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 0
	if _, err := c.Start(context.Background(), p, Job{Depth: 1, MaxNodes: 20}, CompanyRef{ExtID: "root"}); err != nil {
		t.Fatal(err)
	}
	waitFinish(t, st, 1)
	// 上游永远返回 more=true，但 maxPageWalk 硬上限兜底，任务应正常收尾。
	_, finished, _, domains, _ := st.snapshot()
	if finished[len(finished)-1].status != "waiting_authorization" {
		t.Fatalf("status = %q", finished[len(finished)-1].status)
	}
	if len(domains) != c.maxPageWalk {
		t.Fatalf("domains = %d, want %d（maxPageWalk 上限）", len(domains), c.maxPageWalk)
	}
}

// TestCollectorWalkDomainPaceCancel 覆盖 walk 域名翻页循环内的 pace 错误返回分支。
func TestCollectorWalkDomainPaceCancel(t *testing.T) {
	st := &fakeStore{insertAllow: true, domainAllow: true}
	// 详情成功且带域名，域名列表第一页后经长节流 + 取消触发 pace 错误。
	p := &detailProvider{
		name:        "p",
		details:     map[string]*CompanyDetail{"root": {ExtID: "root", Name: "R", Domains: []DomainHit{{Domain: "d.com"}}}},
		domainsMore: map[string]bool{"root": true},
		domains:     map[string][]DomainHit{"root": {{Domain: "a.com"}}},
	}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 10 * time.Second

	job, err := c.Start(context.Background(), p, Job{Depth: 1, MaxNodes: 20}, CompanyRef{ExtID: "root"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	c.Cancel(job.ID)
	waitFinish(t, st, 1)
	_, finished, _, _, _ := st.snapshot()
	if finished[len(finished)-1].status != "canceled" {
		t.Fatalf("status = %q, want canceled", finished[len(finished)-1].status)
	}
}

// TestCollectorCollectChildrenPaceCancel 覆盖 collectChildren 内层 pace 错误返回分支。
func TestCollectorCollectChildrenPaceCancel(t *testing.T) {
	st := &fakeStore{insertAllow: true}
	p := &detailProvider{
		name:     "p",
		brMore:   map[string]bool{"root": true},
		branches: map[string][]CompanyRef{"root": {{ExtID: "b1", Name: "分"}}},
	}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 10 * time.Second

	job, err := c.Start(context.Background(), p, Job{Depth: 2, MaxNodes: 20}, CompanyRef{ExtID: "root"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	c.Cancel(job.ID)
	waitFinish(t, st, 1)
	_, finished, _, _, _ := st.snapshot()
	if finished[len(finished)-1].status != "canceled" {
		t.Fatalf("status = %q, want canceled", finished[len(finished)-1].status)
	}
}

// paceCancelProvider 在列表翻页过程中主动取消任务，用于确定性覆盖 walk /
// collectChildren 翻页循环内的 pace 错误返回分支。
type paceCancelProvider struct {
	name  string
	col   *Collector
	jobID string
}

func (p *paceCancelProvider) Name() string { return p.name }
func (p *paceCancelProvider) Search(context.Context, string, int) ([]CompanyRef, error) {
	return nil, errors.New("not used")
}
func (p *paceCancelProvider) Detail(_ context.Context, extID string) (*CompanyDetail, error) {
	return &CompanyDetail{ExtID: extID, Name: "R"}, nil
}
func (p *paceCancelProvider) Domains(context.Context, string, int, int) ([]DomainHit, bool, error) {
	// 第一页返回 more=true，同时取消 -> 下一页 pace 立即失败。
	p.col.Cancel(p.jobID)
	return []DomainHit{{Domain: "a.com"}}, true, nil
}
func (p *paceCancelProvider) Branches(context.Context, string, int, int) ([]CompanyRef, bool, error) {
	return nil, false, nil
}
func (p *paceCancelProvider) Investments(context.Context, string, int, int) ([]CompanyRef, bool, error) {
	return nil, false, nil
}

// collectCancelProvider 在分支列表第一页取消，覆盖 collectChildren 内层 pace 分支。
type collectCancelProvider struct {
	paceCancelProvider
}

func (p *collectCancelProvider) Domains(context.Context, string, int, int) ([]DomainHit, bool, error) {
	return nil, false, nil
}
func (p *collectCancelProvider) Branches(context.Context, string, int, int) ([]CompanyRef, bool, error) {
	p.col.Cancel(p.jobID)
	return []CompanyRef{{ExtID: "b1", Name: "分"}}, true, nil
}

func TestCollectorWalkDomainPaceCancelDeterministic(t *testing.T) {
	st := &fakeStore{insertAllow: true, domainAllow: true}
	c := NewCollector(st, 20, nil)
	c.rateLimit = time.Millisecond
	p := &paceCancelProvider{name: "p", col: c, jobID: "job-1"}
	if _, err := c.Start(context.Background(), p, Job{Depth: 1, MaxNodes: 20}, CompanyRef{ExtID: "root"}); err != nil {
		t.Fatal(err)
	}
	waitFinish(t, st, 1)
	_, finished, _, _, _ := st.snapshot()
	if finished[len(finished)-1].status != "canceled" {
		t.Fatalf("status = %q, want canceled", finished[len(finished)-1].status)
	}
}

func TestCollectorCollectChildrenPaceCancelDeterministic(t *testing.T) {
	st := &fakeStore{insertAllow: true}
	c := NewCollector(st, 20, nil)
	c.rateLimit = time.Millisecond
	p := &collectCancelProvider{paceCancelProvider{name: "p", col: c, jobID: "job-1"}}
	if _, err := c.Start(context.Background(), p, Job{Depth: 2, MaxNodes: 20}, CompanyRef{ExtID: "root"}); err != nil {
		t.Fatal(err)
	}
	waitFinish(t, st, 1)
	_, finished, _, _, _ := st.snapshot()
	if finished[len(finished)-1].status != "canceled" {
		t.Fatalf("status = %q, want canceled", finished[len(finished)-1].status)
	}
}
