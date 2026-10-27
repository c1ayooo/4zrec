package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// idemCache reuses the result of a repeated call within a time window. Agents
// retry after timeouts; without this, one command-injection probe fires three
// times, burning request budget and leaving obvious traces in target logs.
type idemCache struct {
	mu      sync.Mutex
	window  time.Duration
	now     func() time.Time
	entries map[string]idemEntry
}

type idemEntry struct {
	expires time.Time
	res     core.Result
}

func newIdemCache(window time.Duration, now func() time.Time) *idemCache {
	if window <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &idemCache{window: window, now: now, entries: map[string]idemEntry{}}
}

// idempotencyKey hashes tool + project + actor + task + input. The key is
// derived, not caller-supplied, so a retry after a timeout cannot accidentally
// reuse a different request's result. The tool name is part of the key: two
// different tools that happen to receive byte-identical input (a session_id is
// enough) must never share a cache entry.
func idempotencyKey(tool string, cc core.CallContext, input []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte("tool:"))
	_, _ = h.Write([]byte(tool))
	_, _ = h.Write([]byte("\nproject:"))
	writeInt(h, cc.ProjectID)
	_, _ = h.Write([]byte("\nactor:"))
	_, _ = h.Write([]byte(cc.Actor))
	_, _ = h.Write([]byte("\ntask:"))
	_, _ = h.Write([]byte(cc.TaskID))
	_, _ = h.Write([]byte("\ninput:"))
	_, _ = h.Write(input)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:])
}

func writeInt[T int64 | int](h interface{ Write([]byte) (int, error) }, v T) {
	var buf [20]byte
	i := len(buf)
	if v == 0 {
		i--
		buf[i] = '0'
	} else {
		neg := v < 0
		x := v
		if neg {
			x = -x
		}
		for x > 0 {
			i--
			buf[i] = byte('0' + x%10)
			x /= 10
		}
		if neg {
			i--
			buf[i] = '-'
		}
	}
	_, _ = h.Write(buf[i:])
}

func (c *idemCache) get(key string) (core.Result, bool) {
	if c == nil {
		return core.Result{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return core.Result{}, false
	}
	if c.now().After(e.expires) {
		delete(c.entries, key)
		return core.Result{}, false
	}
	return e.res, true
}

func (c *idemCache) put(key string, res core.Result) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 4096 {
		for k, v := range c.entries {
			if c.now().After(v.expires) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = idemEntry{expires: c.now().Add(c.window), res: res}
}
