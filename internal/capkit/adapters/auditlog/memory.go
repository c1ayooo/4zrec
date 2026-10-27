package auditlog

import (
	"context"
	"sync"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Memory is an in-memory AuditSink for tests and examples.
type Memory struct {
	mu     sync.Mutex
	events []core.AuditEvent
}

func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Record(_ context.Context, ev core.AuditEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

func (m *Memory) Events() []core.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]core.AuditEvent, len(m.events))
	copy(out, m.events)
	return out
}
