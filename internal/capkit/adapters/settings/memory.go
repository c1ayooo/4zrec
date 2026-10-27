package settings

import (
	"context"
	"sync"
)

// Memory is a map-backed Settings implementation for tests/examples.
type Memory struct {
	mu     sync.RWMutex
	values map[string]any
}

func New(values map[string]any) *Memory {
	cp := map[string]any{}
	for k, v := range values {
		cp[k] = v
	}
	return &Memory{values: cp}
}

func (m *Memory) Set(key string, value any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
}

func (m *Memory) GetString(_ context.Context, key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (m *Memory) GetBool(_ context.Context, key string) (bool, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func (m *Memory) GetInt(_ context.Context, key string) (int64, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	}
	return 0, false
}
