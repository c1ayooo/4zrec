package delivery

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

var ErrNotFound = errors.New("delivery record not found")

// Store is the persistence contract. The reference implementation is
// MemoryStore; a host may implement PostgreSQL/MySQL/etc. The contract tests
// should run against MemoryStore first.
type Store interface {
	Create(ctx context.Context, rec *Record) (int64, error)
	Update(ctx context.Context, rec *Record) error
	Get(ctx context.Context, id int64) (*Record, error)
	List(ctx context.Context, projectID int64, limit int) ([]*Record, error)
}

// MemoryStore is the reference Store implementation.
type MemoryStore struct {
	mu   sync.Mutex
	next int64
	byID map[int64]*Record
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byID: map[int64]*Record{}}
}

func (m *MemoryStore) Create(_ context.Context, rec *Record) (int64, error) {
	if rec == nil {
		return 0, errors.New("nil record")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	cp := cloneRecord(rec)
	cp.ID = m.next
	now := time.Now()
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	}
	cp.UpdatedAt = now
	m.byID[cp.ID] = cp
	rec.ID = cp.ID
	rec.CreatedAt = cp.CreatedAt
	rec.UpdatedAt = cp.UpdatedAt
	return cp.ID, nil
}

func (m *MemoryStore) Update(_ context.Context, rec *Record) error {
	if rec == nil || rec.ID <= 0 {
		return errors.New("record id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[rec.ID]; !ok {
		return ErrNotFound
	}
	cp := cloneRecord(rec)
	cp.UpdatedAt = time.Now()
	rec.UpdatedAt = cp.UpdatedAt
	m.byID[cp.ID] = cp
	return nil
}

func (m *MemoryStore) Get(_ context.Context, id int64) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneRecord(rec), nil
}

func (m *MemoryStore) List(_ context.Context, projectID int64, limit int) ([]*Record, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Record, 0, len(m.byID))
	for _, rec := range m.byID {
		if projectID > 0 && rec.ProjectID != projectID {
			continue
		}
		out = append(out, cloneRecord(rec))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func cloneRecord(rec *Record) *Record {
	cp := *rec
	if rec.Plan.Payload.Content != nil {
		cp.Plan.Payload.Content = append([]byte(nil), rec.Plan.Payload.Content...)
	}
	if rec.Plan.FormFields != nil {
		cp.Plan.FormFields = map[string]string{}
		for k, v := range rec.Plan.FormFields {
			cp.Plan.FormFields[k] = v
		}
	}
	if rec.Result != nil {
		r := *rec.Result
		cp.Result = &r
	}
	if rec.ConnectionID != nil {
		v := *rec.ConnectionID
		cp.ConnectionID = &v
	}
	if rec.CleanedAt != nil {
		t := *rec.CleanedAt
		cp.CleanedAt = &t
	}
	return &cp
}
