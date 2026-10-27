package enterprise

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore 记录采集器落库调用，可按钩子注入错误。
type fakeStore struct {
	mu          sync.Mutex
	created     []Job
	finished    []finishCall
	fps         []string
	entities    []*Entity
	domains     []domainCall
	bumps       []bumpCall
	createErr   error
	entityErr   error
	domainErr   error
	bumpErr     error
	insertAllow bool
	domainAllow bool
}

type finishCall struct {
	ID, status, msg string
}

type domainCall struct {
	jobID, domain, site, icp, name string
}

type bumpCall struct {
	id                  string
	nodes, ents, domins int
}

func (s *fakeStore) CreateJob(_ context.Context, job Job) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createErr != nil {
		return Job{}, s.createErr
	}
	job.ID = "job-1"
	job.Status = "running"
	s.created = append(s.created, job)
	return job, nil
}

func (s *fakeStore) FinishJob(_ context.Context, id, status, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = append(s.finished, finishCall{id, status, errMsg})
	return nil
}

func (s *fakeStore) SetFingerprintStatus(_ context.Context, id, status, errMsg string, stats FingerprintStats) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fps = append(s.fps, id+"|"+status+"|"+errMsg+"|"+itoa(stats.Total))
	return nil
}

func (s *fakeStore) SaveEntity(_ context.Context, e *Entity) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entityErr != nil {
		return false, s.entityErr
	}
	s.entities = append(s.entities, e)
	return s.insertAllow, nil
}

func (s *fakeStore) SaveDomain(_ context.Context, jobID, domain, site, icp, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.domainErr != nil {
		return false, s.domainErr
	}
	s.domains = append(s.domains, domainCall{jobID, domain, site, icp, name})
	return s.domainAllow, nil
}

func (s *fakeStore) BumpJob(_ context.Context, id string, nodes, entities, domains int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bumpErr != nil {
		return s.bumpErr
	}
	s.bumps = append(s.bumps, bumpCall{id, nodes, entities, domains})
	return nil
}

func (s *fakeStore) snapshot() (created []Job, finished []finishCall, entities []*Entity, domains []domainCall, bumps []bumpCall) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.created, s.finished, s.entities, s.domains, s.bumps
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// detailProvider 按 extID 返回预置详情，可注入错误与列表数据。
type detailProvider struct {
	name        string
	details     map[string]*CompanyDetail
	detailErr   error
	domains     map[string][]DomainHit
	domainsMore map[string]bool
	branches    map[string][]CompanyRef
	invests     map[string][]CompanyRef
	brMore      map[string]bool
	inMore      map[string]bool
	failOn      map[string]bool
}

func (p *detailProvider) Name() string { return p.name }

func (p *detailProvider) Search(context.Context, string, int) ([]CompanyRef, error) {
	return nil, errors.New("not used")
}

func (p *detailProvider) Detail(_ context.Context, extID string) (*CompanyDetail, error) {
	if p.detailErr != nil {
		return nil, p.detailErr
	}
	if p.failOn != nil && p.failOn["detail:"+extID] {
		return nil, errors.New("detail fail " + extID)
	}
	if d, ok := p.details[extID]; ok {
		return d, nil
	}
	return &CompanyDetail{ExtID: extID, Name: "公司" + extID}, nil
}

func (p *detailProvider) Domains(_ context.Context, extID string, _, _ int) ([]DomainHit, bool, error) {
	if p.failOn != nil && p.failOn["domains:"+extID] {
		return nil, false, errors.New("domains fail")
	}
	return p.domains[extID], p.domainsMore[extID], nil
}

func (p *detailProvider) Branches(_ context.Context, extID string, _, _ int) ([]CompanyRef, bool, error) {
	if p.failOn != nil && p.failOn["branches:"+extID] {
		return nil, false, errors.New("branches fail")
	}
	return p.branches[extID], p.brMore[extID], nil
}

func (p *detailProvider) Investments(_ context.Context, extID string, _, _ int) ([]CompanyRef, bool, error) {
	if p.failOn != nil && p.failOn["invests:"+extID] {
		return nil, false, errors.New("invests fail")
	}
	return p.invests[extID], p.inMore[extID], nil
}

func TestNewCollector(t *testing.T) {
	st := &fakeStore{}
	c := NewCollector(st, 0, nil)
	if c.maxNodes != 20 || c.pageSize != 10 || c.maxPageWalk != 5 || c.rateLimit != 800*time.Millisecond {
		t.Fatalf("默认值错误: %+v", c)
	}
	if c.log == nil {
		t.Fatal("nil logger 应回落 log.Default()")
	}
	c2 := NewCollector(st, 50, nil)
	if c2.maxNodes != 50 {
		t.Fatalf("maxNodes 应保留: %d", c2.maxNodes)
	}
	c2.SetFingerprintScanner(func(context.Context, []string, string, string) (FingerprintStats, error) {
		return FingerprintStats{}, nil
	})
	if c2.scanner == nil {
		t.Fatal("SetFingerprintScanner 未设置")
	}
}

func TestCollectorStartClamp(t *testing.T) {
	st := &fakeStore{}
	c := NewCollector(st, 5, nil)
	job, err := c.Start(context.Background(), fakeProvider{name: "fake"}, Job{Depth: 0, MaxNodes: 999}, CompanyRef{ExtID: "r", Name: "Root"})
	if err != nil {
		t.Fatal(err)
	}
	if job.Depth != 1 {
		t.Fatalf("depth<1 应抬到 1，得到 %d", job.Depth)
	}
	if job.MaxNodes != 5 {
		t.Fatalf("maxNodes 应被 c.maxNodes 收敛，得到 %d", job.MaxNodes)
	}
}

func TestCollectorStartCreateJobError(t *testing.T) {
	st := &fakeStore{createErr: errors.New("db down")}
	c := NewCollector(st, 10, nil)
	if _, err := c.Start(context.Background(), &detailProvider{name: "p"}, Job{Depth: 1, MaxNodes: 5}, CompanyRef{ExtID: "x"}); err == nil {
		t.Fatal("CreateJob 失败应返回错误")
	}
}

func TestCollectorWalkHappy(t *testing.T) {
	st := &fakeStore{insertAllow: true, domainAllow: true}
	p := &detailProvider{
		name: "p",
		details: map[string]*CompanyDetail{
			"root": {ExtID: "root", Name: "母公司", LegalPerson: "张三", OpenStatus: "存续", Phone: "010", Email: "a@b.com",
				Domains: []DomainHit{{Domain: "detail-a.com", Site: "详情站", ICP: "京ICP0"}}},
		},
		domains:     map[string][]DomainHit{"root": {{Domain: "https://A.com/x", Site: "官网", ICP: "京ICP1"}, {Domain: "b.com", Site: "S", ICP: "京ICP2"}}},
		domainsMore: map[string]bool{"root": false},
		branches:    map[string][]CompanyRef{"root": {{ExtID: "b1", Name: "分公司"}}},
		brMore:      map[string]bool{"root": false},
		invests:     map[string][]CompanyRef{"root": {{ExtID: "i1", Name: "被投"}}},
		inMore:      map[string]bool{"root": false},
	}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 0 // 免节流
	c.SetFingerprintScanner(nil)

	job, err := c.Start(context.Background(), p, Job{Depth: 2, MaxNodes: 20}, CompanyRef{ExtID: "root", Name: "母公司"})
	if err != nil {
		t.Fatal(err)
	}

	waitFinish(t, st, 1)

	_, finished, entities, domains, bumps := st.snapshot()
	if len(entities) != 3 {
		t.Fatalf("entities = %d, want 3 (root+branch+invest)", len(entities))
	}
	if entities[0].EntityType != "root" || entities[1].EntityType != "branch" || entities[2].EntityType != "invest" {
		t.Fatalf("entity types = %s/%s/%s", entities[0].EntityType, entities[1].EntityType, entities[2].EntityType)
	}
	if entities[0].Depth != 0 || entities[1].Depth != 1 || entities[1].ParentExtID != "root" {
		t.Fatalf("层级关系错误: %+v", entities[1])
	}
	if entities[0].Name != "母公司" || entities[0].LegalPerson != "张三" {
		t.Fatalf("root 详情未落库: %+v", entities[0])
	}
	if len(domains) != 3 { // 1 条详情 + 2 条列表
		t.Fatalf("domains 落库 = %d, want 3", len(domains))
	}
	// 采集器保存原始 domain 串（归一化由上层候选资产逻辑负责）。
	if domains[0].domain != "detail-a.com" || domains[0].site != "详情站" || domains[0].icp != "京ICP0" {
		t.Fatalf("domain[0] = %+v", domains[0])
	}
	if domains[2].domain != "b.com" || domains[2].site != "S" {
		t.Fatalf("domain[2] = %+v", domains[2])
	}
	if len(bumps) != 3 {
		t.Fatalf("bumps = %d, want 3", len(bumps))
	}
	if bumps[0].ents != 1 || bumps[0].domins != 3 {
		t.Fatalf("bump 计数错误: %+v", bumps[0])
	}
	if len(finished) == 0 {
		t.Fatal("未调用 FinishJob")
	}
	last := finished[len(finished)-1]
	if last.status != "waiting_authorization" {
		t.Fatalf("完成状态 = %q", last.status)
	}
	if !strings.Contains(st.fps[len(st.fps)-1], "waiting_authorization") {
		t.Fatalf("指纹状态未落库: %v", st.fps)
	}
	_ = job
}

func TestCollectorWalkErrors(t *testing.T) {
	t.Run("详情失败 → error", func(t *testing.T) {
		st := &fakeStore{}
		p := &detailProvider{name: "p", detailErr: errors.New("boom")}
		c := NewCollector(st, 20, nil)
		c.rateLimit = 0
		if _, err := c.Start(context.Background(), p, Job{Depth: 1, MaxNodes: 5}, CompanyRef{ExtID: "r"}); err != nil {
			t.Fatal(err)
		}
		waitFinish(t, st, 1)
		_, finished, _, _, _ := st.snapshot()
		if finished[len(finished)-1].status != "error" {
			t.Fatalf("status = %q", finished[len(finished)-1].status)
		}
	})

	t.Run("保存实体失败 → error", func(t *testing.T) {
		st := &fakeStore{entityErr: errors.New("save fail")}
		c := NewCollector(st, 20, nil)
		c.rateLimit = 0
		if _, err := c.Start(context.Background(), &detailProvider{name: "p"}, Job{Depth: 1, MaxNodes: 5}, CompanyRef{ExtID: "r"}); err != nil {
			t.Fatal(err)
		}
		waitFinish(t, st, 1)
		_, finished, _, _, _ := st.snapshot()
		if finished[len(finished)-1].status != "error" {
			t.Fatalf("status = %q", finished[len(finished)-1].status)
		}
	})

	t.Run("BumpJob 失败 → error", func(t *testing.T) {
		st := &fakeStore{bumpErr: errors.New("bump fail")}
		c := NewCollector(st, 20, nil)
		c.rateLimit = 0
		if _, err := c.Start(context.Background(), &detailProvider{name: "p"}, Job{Depth: 1, MaxNodes: 5}, CompanyRef{ExtID: "r"}); err != nil {
			t.Fatal(err)
		}
		waitFinish(t, st, 1)
		_, finished, _, _, _ := st.snapshot()
		if finished[len(finished)-1].status != "error" {
			t.Fatalf("status = %q", finished[len(finished)-1].status)
		}
	})

	t.Run("达到节点上限", func(t *testing.T) {
		st := &fakeStore{insertAllow: true}
		p := &detailProvider{
			name:     "p",
			branches: map[string][]CompanyRef{"root": {{ExtID: "b1"}, {ExtID: "b2"}}},
			invests:  map[string][]CompanyRef{"root": {{ExtID: "i1"}, {ExtID: "i2"}}},
		}
		c := NewCollector(st, 20, nil)
		c.rateLimit = 0
		if _, err := c.Start(context.Background(), p, Job{Depth: 2, MaxNodes: 1}, CompanyRef{ExtID: "root"}); err != nil {
			t.Fatal(err)
		}
		waitFinish(t, st, 1)
		_, finished, _, _, _ := st.snapshot()
		if finished[len(finished)-1].status != "error" {
			t.Fatalf("status = %q", finished[len(finished)-1].status)
		}
	})

	t.Run("域名/分支列表失败不致命", func(t *testing.T) {
		st := &fakeStore{insertAllow: true}
		p := &detailProvider{
			name:    "p",
			details: map[string]*CompanyDetail{"root": {ExtID: "root", Name: "R", Domains: []DomainHit{{Domain: "keep.com"}}}},
			failOn:  map[string]bool{"domains:root": true, "branches:root": true, "invests:root": true},
		}
		c := NewCollector(st, 20, nil)
		c.rateLimit = 0
		if _, err := c.Start(context.Background(), p, Job{Depth: 1, MaxNodes: 5}, CompanyRef{ExtID: "root"}); err != nil {
			t.Fatal(err)
		}
		waitFinish(t, st, 1)
		_, finished, _, domains, _ := st.snapshot()
		if finished[len(finished)-1].status != "waiting_authorization" {
			t.Fatalf("status = %q", finished[len(finished)-1].status)
		}
		if len(domains) != 1 || domains[0].domain != "keep.com" {
			t.Fatalf("详情里的域名仍应保存: %+v", domains)
		}
	})

	t.Run("已访问节点不重复入队", func(t *testing.T) {
		st := &fakeStore{insertAllow: true}
		p := &detailProvider{
			name:     "p",
			branches: map[string][]CompanyRef{"root": {{ExtID: "root", Name: "自引用"}, {ExtID: "b1", Name: "分公司"}}},
			invests:  map[string][]CompanyRef{"root": {{ExtID: "b1", Name: "重复"}}},
		}
		c := NewCollector(st, 20, nil)
		c.rateLimit = 0
		if _, err := c.Start(context.Background(), p, Job{Depth: 3, MaxNodes: 20}, CompanyRef{ExtID: "root"}); err != nil {
			t.Fatal(err)
		}
		waitFinish(t, st, 1)
		_, _, entities, _, _ := st.snapshot()
		if len(entities) != 2 {
			t.Fatalf("entities = %d, want 2 (root + b1)", len(entities))
		}
	})
}

func TestCollectorCancel(t *testing.T) {
	st := &fakeStore{}
	p := &detailProvider{name: "p"}
	c := NewCollector(st, 20, nil)
	c.rateLimit = 50 * time.Millisecond

	job, err := c.Start(context.Background(), p, Job{Depth: 1, MaxNodes: 20}, CompanyRef{ExtID: "root"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Cancel(job.ID) {
		t.Fatal("Cancel 运行中的任务应返回 true")
	}
	waitFinish(t, st, 1)
	_, finished, _, _, _ := st.snapshot()
	if finished[len(finished)-1].status != "canceled" {
		t.Fatalf("status = %q, want canceled", finished[len(finished)-1].status)
	}
	if c.Cancel(job.ID) {
		t.Fatal("任务结束后 Cancel 应返回 false")
	}
	if c.Cancel("never-existed") {
		t.Fatal("未知 ID Cancel 应返回 false")
	}
}

func TestCollectorPace(t *testing.T) {
	c := NewCollector(&fakeStore{}, 10, nil)
	if err := c.pace(context.Background()); err != nil {
		t.Fatalf("pace = %v", err)
	}
	c.rateLimit = 0
	if err := c.pace(context.Background()); err != nil {
		t.Fatalf("rateLimit<=0 应直接返回: %v", err)
	}
	// 已取消的 context：需在起 timer 前就返回，用正常限速的新 collector。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := NewCollector(&fakeStore{}, 10, nil)
	slow.rateLimit = 30 * time.Second
	if err := slow.pace(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pace err = %v, want context.Canceled", err)
	}
}

func TestCollectorForget(t *testing.T) {
	c := NewCollector(&fakeStore{}, 10, nil)
	c.mu.Lock()
	c.running["j"] = &runningJob{cancel: func() {}}
	c.mu.Unlock()
	c.forget("j")
	c.mu.Lock()
	_, ok := c.running["j"]
	c.mu.Unlock()
	if ok {
		t.Fatal("forget 未清理 running")
	}
}

// waitFinish 轮询等待任务落库完成。
func waitFinish(t *testing.T, st *fakeStore, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st.mu.Lock()
		n := len(st.finished)
		st.mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	st.mu.Lock()
	n := len(st.finished)
	st.mu.Unlock()
	t.Fatalf("等待 FinishJob 超时，已有 %d 次落库", n)
}
