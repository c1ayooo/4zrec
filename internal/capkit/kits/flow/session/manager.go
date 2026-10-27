// Package sessionkit implements the capkit Session contract (docs §5.1) and
// the openers for it. A new transport only implements Session's three methods
// plus SessionManager plumbing; every downstream kit (privesc, lat, persist,
// cleanup, internalnet, container) then works against it unchanged.
//
// SessionManager is a port owned by the host. This package supplies a default
// implementation plus an SSH adapter (real connections, host-injected key
// material) and a CLI adapter (local command execution) so the contract is
// exercised end to end without a host-side implementation.
package session

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ---- Manager ----

// Manager is the default SessionManager. Openers are registered per kind
// ("ssh", "winrm", "smb", "cli", "webshell", ...) by the host; the manager
// tracks live sessions by ID and hands out Sessions to callers.
type Manager struct {
	mu       sync.RWMutex
	openers  map[string]core.SessionOpener
	sessions map[string]core.Session
	info     map[string]core.SessionInfo
	newID    func(string) string
	now      func() time.Time
}

// NewManager builds a Manager. idFn/nowFn are optional (defaults: random-ish
// counter id, time.Now).
func NewManager(idFn func(string) string, nowFn func() time.Time) *Manager {
	m := &Manager{
		openers:  map[string]core.SessionOpener{},
		sessions: map[string]core.Session{},
		info:     map[string]core.SessionInfo{},
		newID:    idFn, now: nowFn,
	}
	if m.newID == nil {
		counter := int64(0)
		m.newID = func(prefix string) string {
			m.mu.Lock()
			counter++
			c := counter
			m.mu.Unlock()
			return fmt.Sprintf("%s-%d-%d", prefix, m.now().UnixNano(), c)
		}
	}
	if m.now == nil {
		m.now = time.Now
	}
	return m
}

// RegisterOpener installs an opener for a session kind.
func (m *Manager) RegisterOpener(kind string, opener core.SessionOpener) {
	if strings.TrimSpace(kind) == "" || opener == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.openers[strings.ToLower(kind)] = opener
}

// Open creates and tracks a session.
func (m *Manager) Open(ctx context.Context, spec core.SessionSpec) (core.SessionInfo, error) {
	kind := strings.ToLower(strings.TrimSpace(spec.Kind))
	if kind == "" {
		return core.SessionInfo{}, fmt.Errorf("kind 必填（ssh|winrm|smb|cli|webshell|...）")
	}
	m.mu.RLock()
	opener, ok := m.openers[kind]
	m.mu.RUnlock()
	if !ok {
		return core.SessionInfo{}, fmt.Errorf("没有注册 %s 的 SessionOpener", kind)
	}
	if strings.TrimSpace(spec.Host) == "" {
		return core.SessionInfo{}, fmt.Errorf("host 必填")
	}
	if spec.Port == 0 {
		spec.Port = defaultPort(kind)
	}
	if spec.Timeout == 0 {
		spec.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()

	s, err := opener.Open(ctx, spec)
	if err != nil {
		return core.SessionInfo{}, err
	}
	info := s.Info()
	if info.ID == "" {
		info.ID = m.newID("sess")
	}
	if info.Kind == "" {
		info.Kind = kind
	}
	if info.Host == "" {
		info.Host = spec.Host
	}
	if info.Port == 0 {
		info.Port = spec.Port
	}
	if info.User == "" {
		info.User = spec.User
	}
	m.mu.Lock()
	m.sessions[info.ID] = s
	m.info[info.ID] = info
	m.mu.Unlock()
	return info, nil
}

// Get returns a live session by ID.
func (m *Manager) Get(id string) (core.Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// List returns metadata for all live sessions, ordered by ID.
func (m *Manager) List() []core.SessionInfo {
	m.mu.RLock()
	out := make([]core.SessionInfo, 0, len(m.info))
	for _, i := range m.info {
		out = append(out, i)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Close closes and untracks one session. Closing an unknown ID is not an error
// (idempotent: agents retry after timeouts).
func (m *Manager) Close(id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
		delete(m.info, id)
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return s.Close()
}

// CloseAll closes every tracked session and returns the joined errors.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	sessions := m.sessions
	m.sessions = map[string]core.Session{}
	m.info = map[string]core.SessionInfo{}
	m.mu.Unlock()
	var errs []error
	for _, id := range ids {
		if err := sessions[id].Close(); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func defaultPort(kind string) int {
	switch kind {
	case "ssh":
		return 22
	case "winrm":
		return 5985
	case "smb":
		return 445
	case "cli":
		return 0
	default:
		return 0
	}
}
