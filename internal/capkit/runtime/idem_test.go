package runtime

import (
	"encoding/json"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// TestIdempotencyKeyIncludesTool is a regression guard: the key must fold in
// the tool name, or two different tools that receive byte-identical input
// (a bare {"session_id":"x"} is enough) collide and return each other's cached
// result.
func TestIdempotencyKeyIncludesTool(t *testing.T) {
	cc := core.CallContext{ProjectID: 1, Actor: "a", TaskID: "t"}
	in := json.RawMessage(`{"session_id":"x"}`)

	k1 := idempotencyKey("session_list", cc, in)
	k2 := idempotencyKey("session_close", cc, in)
	if k1 == k2 {
		t.Fatal("different tools produced the same idempotency key")
	}

	// Same tool, same context, same input is stable (so a genuine retry hits).
	if k1 != idempotencyKey("session_list", cc, in) {
		t.Fatal("the same call must produce a stable key")
	}

	// A different actor must not share a cache entry.
	cc2 := cc
	cc2.Actor = "b"
	if k1 == idempotencyKey("session_list", cc2, in) {
		t.Fatal("different actors must not share a cache entry")
	}

	// A different project must not share a cache entry.
	cc3 := cc
	cc3.ProjectID = 2
	if k1 == idempotencyKey("session_list", cc3, in) {
		t.Fatal("different projects must not share a cache entry")
	}
}
