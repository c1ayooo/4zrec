package internalnet

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// This file provides the fake Session and fake SessionManager the tests drive.
// Nothing here touches the real network: every command returns a canned output
// scripted by the test, so the whole suite is hermetic.

var (
	_ core.Session        = (*scriptedSession)(nil)
	_ core.SessionManager = (*fakeManager)(nil)
)

// rule maps a command (matched by substring, first match wins) to an output.
type rule struct {
	match      string
	stdout     string
	stderr     string
	exit       int
	evidenceID string
	err        error
}

// scriptedSession is a core.Session that answers from a rule table. It is
// safe for concurrent Exec calls, matching the Session contract.
type scriptedSession struct {
	info  core.SessionInfo
	rules []rule

	mu     sync.Mutex
	calls  []string
	closed bool
}

func (s *scriptedSession) Exec(_ context.Context, cmd string, _ core.ExecOpts) (core.Output, error) {
	s.mu.Lock()
	s.calls = append(s.calls, cmd)
	rules := s.rules
	s.mu.Unlock()
	for _, r := range rules {
		if strings.Contains(cmd, r.match) {
			if r.err != nil {
				return core.Output{Command: cmd}, r.err
			}
			return core.Output{
				Command: cmd, Stdout: r.stdout, Stderr: r.stderr,
				ExitCode: r.exit, EvidenceID: r.evidenceID,
			}, nil
		}
	}
	return core.Output{Command: cmd, ExitCode: 0}, nil
}

func (s *scriptedSession) Info() core.SessionInfo { return s.info }

func (s *scriptedSession) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *scriptedSession) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// fakeManager is a core.SessionManager backed by an in-memory map.
type fakeManager struct {
	sessions map[string]core.Session
	infos    map[string]core.SessionInfo
}

func newFakeManager() *fakeManager {
	return &fakeManager{sessions: map[string]core.Session{}, infos: map[string]core.SessionInfo{}}
}

func (m *fakeManager) add(s *scriptedSession) {
	m.sessions[s.info.ID] = s
	m.infos[s.info.ID] = s.info
}

func (m *fakeManager) Open(context.Context, core.SessionSpec) (core.SessionInfo, error) {
	return core.SessionInfo{}, errors.New("not implemented")
}

func (m *fakeManager) Get(id string) (core.Session, bool) {
	s, ok := m.sessions[id]
	return s, ok
}

func (m *fakeManager) List() []core.SessionInfo {
	out := make([]core.SessionInfo, 0, len(m.infos))
	for _, i := range m.infos {
		out = append(out, i)
	}
	return out
}

func (m *fakeManager) Close(id string) error {
	delete(m.sessions, id)
	delete(m.infos, id)
	return nil
}

// capWith builds a capability wired to the given manager, or a bare one when
// manager is nil (the missing-port path).
func capWith(manager core.SessionManager) *Capability {
	c, err := NewCapability(core.Deps{Sessions: manager})
	if err != nil {
		panic(err)
	}
	return c.(*Capability)
}
