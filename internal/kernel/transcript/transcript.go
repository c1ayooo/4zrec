// Package transcript persists a conversation to an append-only JSONL log on
// disk and reconstructs it for resume. The main session is written to
// <dir>/<sessionID>.jsonl; each
// subagent is written to its own sidechain file under
// <dir>/<sessionID>/subagents/agent-<agentID>.jsonl, so subagent tokens are
// counted and stored separately (aggregate them offline if needed).
//
// The log is the full-fidelity history: every user/assistant/tool message is
// recorded as it is born. When compaction inserts a boundary, the post-boundary
// working set — the boundary marker, the summary, and the kept recent tail — is
// ALSO persisted as messages, so a cold-start resume restores the COMPACTED view
// (via acllm.MessagesForAPI, which slices from the last boundary) instead of
// replaying raw history and re-summarizing. The kept tail
// is re-recorded after the boundary (it also exists earlier as births); only the
// post-boundary copy reaches the model. Lightweight working-set edits that do not
// add a boundary (MicroCompact tool-result clearing) stay ephemeral and
// are not persisted. A separate Type=="boundary" record is written for
// observability and is skipped during reconstruction.
package transcript

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
)

// Record is one line of a JSONL transcript.
type Record struct {
	UUID        string              `json:"uuid"`
	ParentUUID  string              `json:"parent_uuid,omitempty"`
	SessionID   string              `json:"session_id"`
	AgentID     string              `json:"agent_id,omitempty"`
	IsSidechain bool                `json:"is_sidechain,omitempty"`
	Timestamp   string              `json:"timestamp"`
	Type        string              `json:"type"` // "message" | "boundary"
	Message     *acllm.Message      `json:"message,omitempty"`
	Usage       *acllm.Usage        `json:"usage,omitempty"`    // assistant turns only
	Boundary    *acllm.BoundaryMeta `json:"boundary,omitempty"` // Type=="boundary"
}

// Store is a directory of session transcripts.
type Store struct {
	dir string
	mu  sync.Mutex // serializes appends across writers in this process
}

// NewStore returns a Store rooted at dir (created lazily on first write).
func NewStore(dir string) *Store { return &Store{dir: dir} }

// MainPath is the JSONL file for a top-level session.
func (s *Store) MainPath(sessionID string) string {
	return filepath.Join(s.dir, sessionID+".jsonl")
}

// AgentPath is the sidechain JSONL file for a subagent of a session.
func (s *Store) AgentPath(sessionID, agentID string) string {
	return filepath.Join(s.dir, sessionID, "subagents", "agent-"+agentID+".jsonl")
}

// Append writes records to path as JSONL, creating parent directories. It is
// safe for concurrent use within the process.
func (s *Store) Append(path string, recs ...Record) error {
	if len(recs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(path), 0o700)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Chmod(0o600)
	w := bufio.NewWriter(f)
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.Flush()
}

// Load reads all records from a transcript file. A missing file yields no
// records and no error (a fresh session).
func (s *Store) Load(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var recs []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024) // tolerate large tool results
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("transcript: corrupt line: %w", err)
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}

// Messages reconstructs the raw conversation and cumulative usage from records.
// Boundary records are skipped — the working set is rebuilt by compaction on the
// next turn, not replayed from disk.
func Messages(recs []Record) ([]acllm.Message, acllm.Usage) {
	var msgs []acllm.Message
	var total acllm.Usage
	for _, r := range recs {
		if r.Type == "boundary" || r.Message == nil {
			continue
		}
		msgs = append(msgs, *r.Message)
		if r.Usage != nil {
			total.Add(*r.Usage)
		}
	}
	return msgs, total
}

// LastUUID returns the UUID of the last record, for continuing the parent chain.
func LastUUID(recs []Record) string {
	if len(recs) == 0 {
		return ""
	}
	return recs[len(recs)-1].UUID
}

// Recorder receives conversation events for durable transcript persistence.
// RecordMessage fires once per new message in birth order; usage carries the
// token delta attributed to that turn (assistant messages only; zero
// otherwise). RecordBoundary fires when compaction inserts a boundary, for
// observability — boundaries are not part of the raw reconstructable history.
type Recorder interface {
	RecordMessage(m acllm.Message, usage acllm.Usage)
	RecordBoundary(meta acllm.BoundaryMeta)
}

// Writer binds a Store, a file path, and a session/agent identity, assigning a
// UUID and parent link to each record. It satisfies Recorder. Append
// errors are retained (see Err) rather than panicking, so a failing disk
// degrades to in-memory operation instead of crashing the agent loop.
type Writer struct {
	store       *Store
	path        string
	sessionID   string
	agentID     string
	isSidechain bool

	mu   sync.Mutex
	last string
	now  func() time.Time
	err  error
}

// NewWriter returns a Writer for a fresh transcript file. agentID == "" writes
// the main session file; a non-empty agentID writes a subagent sidechain.
func (s *Store) NewWriter(sessionID, agentID string) *Writer {
	w := &Writer{store: s, sessionID: sessionID, agentID: agentID, now: time.Now}
	if agentID == "" {
		w.path = s.MainPath(sessionID)
	} else {
		w.path = s.AgentPath(sessionID, agentID)
		w.isSidechain = true
	}
	return w
}

// ResumeWriter returns a Writer that continues an existing main-session file,
// chaining new records after lastUUID.
func (s *Store) ResumeWriter(sessionID, lastUUID string) *Writer {
	w := s.NewWriter(sessionID, "")
	w.last = lastUUID
	return w
}

// Err returns the first append error encountered, if any.
func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *Writer) write(r Record) {
	w.mu.Lock()
	defer w.mu.Unlock()
	r.SessionID = w.sessionID
	r.AgentID = w.agentID
	r.IsSidechain = w.isSidechain
	r.UUID = newID()
	r.ParentUUID = w.last
	r.Timestamp = w.now().UTC().Format(time.RFC3339Nano)
	if err := w.store.Append(w.path, r); err != nil {
		if w.err == nil {
			w.err = err
		}
		return
	}
	w.last = r.UUID
}

// RecordMessage persists a conversation message. usage is attributed to this
// turn (zero for non-assistant messages).
func (w *Writer) RecordMessage(m acllm.Message, usage acllm.Usage) {
	rec := Record{Type: "message", Message: &m}
	if usage != (acllm.Usage{}) {
		u := usage
		rec.Usage = &u
	}
	w.write(rec)
}

// RecordBoundary persists a compaction boundary for observability.
func (w *Writer) RecordBoundary(meta acllm.BoundaryMeta) {
	m := meta
	w.write(Record{Type: "boundary", Boundary: &m})
}

// newID returns a random 128-bit hex identifier.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand should never fail; fall back to a time-based id to stay unique-ish.
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// NewSessionID returns a fresh session identifier.
func NewSessionID() string { return newID() }

// NewAgentID returns a fresh subagent identifier.
func NewAgentID() string { return newID() }
