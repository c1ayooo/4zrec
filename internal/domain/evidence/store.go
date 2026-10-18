// Package evidence preserves finding evidence independently of disposable traffic.
package evidence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/domain/traffic"
)

type Store struct {
	DB      *db.DB
	Traffic *traffic.Traffic
	Dir     string
}

func New(pg *db.DB, tr *traffic.Traffic, dir string) *Store {
	return &Store{DB: pg, Traffic: tr, Dir: dir}
}

func hashPath(dir, hash string) (string, error) {
	if len(hash) != 64 {
		return "", errors.New("invalid evidence hash")
	}
	if _, err := hex.DecodeString(hash); err != nil || strings.ToLower(hash) != hash {
		return "", errors.New("invalid evidence hash")
	}
	return filepath.Join(dir, "blobs", hash[:2], hash+".bin"), nil
}

func verifyFile(path, hash string, length int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if n != length || hex.EncodeToString(h.Sum(nil)) != hash {
		return fmt.Errorf("证据正文校验失败: %s", hash)
	}
	return nil
}

// A new body becomes visible only after a durable write. Failed SQL commits may
// leave unreferenced files; GC reaps those after a full day's grace period.
func (s *Store) writeBody(r io.Reader, expectedLength int64, expectedHash string) (hash string, err error) {
	stage := filepath.Join(s.Dir, ".staging")
	if err = os.MkdirAll(stage, 0o700); err != nil {
		return
	}
	f, err := os.CreateTemp(stage, "body-")
	if err != nil {
		return "", err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return "", err
	}
	hash = hex.EncodeToString(h.Sum(nil))
	if n != expectedLength {
		return "", fmt.Errorf("正文不完整: 预期 %d 字节，读取 %d 字节", expectedLength, n)
	}
	if expectedHash != "" && expectedHash != hash {
		return "", errors.New("原始流量正文哈希不匹配")
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		return "", err
	}
	if _, err = os.Stat(path); err == nil {
		if err = verifyFile(path, hash, n); err != nil {
			return "", err
		}
		// Refresh the grace period for a restored but not-yet-committed body.
		now := time.Now()
		return hash, os.Chtimes(path, now, now)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return "", err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer d.Close()
	return hash, d.Sync()
}

// StageFindingsExport freezes bindings/report versions and makes private body
// copies before the HTTP response is started. The caller owns and removes dest.
func (s *Store) StageFindingsExport(ctx context.Context, findings []*db.DBFinding, dest string, copyBodies bool) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		var snapshots []db.TrafficEvidenceSnapshot
		for _, f := range findings {
			list, err := db.FindingTrafficTx(tx, f.ID)
			if err != nil {
				return err
			}
			f.TrafficBindings = list.Bindings
			f.TrafficCount = len(list.Bindings)
			f.EvidenceVersion = list.Version
			f.ReportEvidenceVersion = list.ReportVersion
			if err = tx.QueryRow(`SELECT report FROM findings WHERE id=$1`, f.ID).Scan(&f.Report); err != nil {
				return err
			}
			for _, b := range list.Bindings {
				snapshots = append(snapshots, b.Snapshot)
			}
		}
		if copyBodies {
			return s.copySnapshots(snapshots, dest)
		}
		return nil
	})
}

func (s *Store) prepare(ctx context.Context, refs []db.TrafficRef) ([]db.PreparedTrafficEvidence, error) {
	refs, err := db.NormalizeTrafficRefs(refs)
	if err != nil {
		return nil, err
	}
	out := make([]db.PreparedTrafficEvidence, 0, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	ids := make([]string, len(refs))
	byID := map[string]db.TrafficRef{}
	for i, ref := range refs {
		ids[i] = ref.TrafficID
		byID[ref.TrafficID] = ref
	}
	err = s.Traffic.ReadEvidence(ctx, ids, func(e traffic.EvidenceExchange) error {
		rh, err := s.writeBody(e.Request, e.ReqLen, e.ReqHash)
		if err != nil {
			return err
		}
		ph, err := s.writeBody(e.Response, e.RespLen, e.RespHash)
		if err != nil {
			return err
		}
		v := db.TrafficEvidenceSnapshot{SourceTrafficID: e.ID, CapturedAt: e.TS, URL: e.URL, Method: e.Method, Status: e.Status, ContentType: e.ContentType,
			ReqHead: e.ReqHead, RespHead: e.RespHead, ReqHash: rh, RespHash: ph, ReqLen: e.ReqLen, RespLen: e.RespLen}
		// Raw wire bytes: normalize once here so the ID, the stored row and every
		// downstream consumer (archive, API responses) all see the same text.
		v = v.Normalize()
		v.ID = db.TrafficSnapshotID(v)
		out = append(out, db.PreparedTrafficEvidence{Ref: byID[e.ID], Snapshot: v})
		return nil
	})
	return out, err
}

func (s *Store) Record(ctx context.Context, in db.RecordFindingInput, refs []db.TrafficRef) (out *db.RecordedFinding, err error) {
	// 模型经常在 evidence 里贴了真实请求/响应，却没有把 http_probe 返回的
	// traffic_id 回填到 traffic_refs。这里按“证据里的请求对象”做一次确定性
	// 匹配：method + host + path 命中平台记录时自动绑定，避免报告只有文字
	// 证据、没有可点击报文。显式传入的 refs 优先，不覆盖模型的选择。
	if len(refs) == 0 {
		refs = s.autoTrafficRefs(ctx, in)
	}
	err = s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := db.LockTaskEvidenceTx(tx, in.TaskID); err != nil {
			return err
		}
		prepared, err := s.prepare(ctx, refs)
		if err != nil {
			return err
		}
		out, err = db.RecordFindingTx(ctx, tx, in, prepared)
		return err
	})
	return
}

func (s *Store) Bind(ctx context.Context, findingID int64, refs []db.TrafficRef) (out *db.FindingTraffic, err error) {
	err = s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if err := db.LockFindingEvidenceTx(tx, findingID, nil); err != nil {
			return err
		}
		prepared, err := s.prepare(ctx, refs)
		if err != nil {
			return err
		}
		if err = db.AddFindingTrafficTx(tx, findingID, prepared); err != nil {
			return err
		}
		out, err = db.FindingTrafficTx(tx, findingID)
		return err
	})
	return
}

func (s *Store) WithBinding(ctx context.Context, findingID, bindingID int64, fn func(db.FindingTrafficBinding) error) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		list, err := db.FindingTrafficTx(tx, findingID)
		if err != nil {
			return err
		}
		for _, b := range list.Bindings {
			if b.ID == bindingID {
				return fn(b)
			}
		}
		return db.ErrEvidenceNotFound
	})
}

// Binding resolves one binding's metadata under the evidence lock and releases
// the lock before returning. Callers that then stream a body to a client must
// use this instead of WithBinding: verifyFile+io.Copy is O(body size), so a
// large download (or a slow client) holding WithEvidenceTx would block every
// evidence write process-wide. Reading the blob afterwards is safe — blobs are
// content-addressed and GC only reaps unreferenced files after a 24h grace
// period, and an already-open fd survives an unlink regardless.
func (s *Store) Binding(ctx context.Context, findingID, bindingID int64) (db.FindingTrafficBinding, error) {
	var out db.FindingTrafficBinding
	err := s.WithBinding(ctx, findingID, bindingID, func(b db.FindingTrafficBinding) error {
		out = b
		return nil
	})
	return out, err
}

// OpenBody may be called without holding the evidence lock; see Binding.
func (s *Store) OpenBody(snapshot db.TrafficEvidenceSnapshot, side string) (*os.File, int64, error) {
	hash, length := snapshot.ReqHash, snapshot.ReqLen
	if side == "response" {
		hash, length = snapshot.RespHash, snapshot.RespLen
	} else if side != "request" {
		return nil, 0, errors.New("side 必须为 request 或 response")
	}
	path, err := hashPath(s.Dir, hash)
	if err != nil {
		return nil, 0, err
	}
	if err = verifyFile(path, hash, length); err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	return f, length, err
}

// CopySnapshots is used by both report downloads and portable task archives.
// The destination owns real copies, never links into either disposable store.
func (s *Store) CopySnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, dest string) error {
	return s.DB.WithEvidenceTx(ctx, func(*sql.Tx) error { return s.copySnapshots(snapshots, dest) })
}

func (s *Store) copySnapshots(snapshots []db.TrafficEvidenceSnapshot, dest string) error {
	for _, v := range snapshots {
		for _, side := range []string{"request", "response"} {
			if err := func() error {
				f, length, err := s.OpenBody(v, side)
				if err != nil {
					return err
				}
				defer f.Close()
				hash := v.ReqHash
				if side == "response" {
					hash = v.RespHash
				}
				target, err := hashPath(dest, hash)
				if err != nil {
					return err
				}
				if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					return err
				}
				out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
				if os.IsExist(err) {
					return verifyFile(target, hash, length)
				}
				if err != nil {
					return err
				}
				_, copyErr := io.Copy(out, f)
				syncErr := out.Sync()
				closeErr := out.Close()
				return errors.Join(copyErr, syncErr, closeErr)
			}(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) InstallSnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, source string) error {
	return s.WithInstalledSnapshots(ctx, snapshots, source, func() error { return nil })
}

// WithInstalledSnapshots pins installed bodies until the metadata restore finishes.
// The callback must not acquire another evidence advisory lock.
func (s *Store) WithInstalledSnapshots(ctx context.Context, snapshots []db.TrafficEvidenceSnapshot, source string, restore func() error) error {
	return s.DB.WithEvidenceTx(ctx, func(*sql.Tx) error {
		for _, v := range snapshots {
			if v.ID != db.TrafficSnapshotID(v) {
				return errors.New("归档证据快照元数据哈希不匹配")
			}
			for _, body := range []struct {
				hash   string
				length int64
			}{{v.ReqHash, v.ReqLen}, {v.RespHash, v.RespLen}} {
				if err := func() error {
					path, err := hashPath(source, body.hash)
					if err != nil {
						return err
					}
					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()
					_, err = s.writeBody(f, body.length, body.hash)
					return err
				}(); err != nil {
					return err
				}
			}
		}
		return restore()
	})
}

func (s *Store) Collect(ctx context.Context, now time.Time) error {
	return s.DB.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE traffic_evidence_snapshots s SET unreferenced_at=$1
WHERE unreferenced_at IS NULL AND NOT EXISTS(SELECT 1 FROM finding_traffic_bindings b WHERE b.snapshot_id=s.id)`, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM traffic_evidence_snapshots s WHERE unreferenced_at<$1
AND NOT EXISTS(SELECT 1 FROM finding_traffic_bindings b WHERE b.snapshot_id=s.id)`, now.Add(-24*time.Hour)); err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT req_hash FROM traffic_evidence_snapshots UNION SELECT resp_hash FROM traffic_evidence_snapshots`)
		if err != nil {
			return err
		}
		refs := map[string]bool{}
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				rows.Close()
				return err
			}
			refs[hash] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, root := range []string{filepath.Join(s.Dir, "blobs"), filepath.Join(s.Dir, ".staging")} {
			err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if os.IsNotExist(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				if refs[strings.TrimSuffix(entry.Name(), ".bin")] {
					return nil
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if now.Sub(info.ModTime()) < 24*time.Hour {
					return nil
				}
				return os.Remove(path)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) RunGC(ctx context.Context) {
	timer := time.NewTicker(time.Hour)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			if err := s.Collect(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[evidence] cleanup failed: %v", err)
			}
		}
	}
}

var (
	reEvidenceURL    = regexp.MustCompile(`https?://[^\s"'<>\\]+`)
	reEvidenceMethod = regexp.MustCompile(`(?i)(?:-X|--request)\s+([A-Z]+)\b`)
	reTrafficID      = regexp.MustCompile(`traffic_id[=:]\s*"?([A-Za-z0-9._-]+)`)
	// 证据里常见的原始请求行：GET /api/x HTTP/1.1 / POST /api/y
	reEvidenceRequestLine = regexp.MustCompile(`(?m)^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s?#]*)`)
	reEvidenceHost        = regexp.MustCompile(`(?im)^\s*Host:\s*([^\s:]+)`)
)

// autoTargetHosts 从 finding 关联资产（service URL / domain / ip）取目标 host；
// 资产缺失时回退到证据里的 Host 头。只用于把相对请求行补成可匹配的 host。
func (s *Store) autoTargetHosts(in db.RecordFindingInput) []string {
	var hosts []string
	seen := map[string]bool{}
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if s.DB != nil && len(in.AssetIDs) > 0 {
		if assets, err := s.DB.Assets().GetByIDs(in.AssetIDs); err == nil {
			for _, a := range assets {
				if a == nil {
					continue
				}
				if a.URL != "" {
					if u, err := url.Parse(a.URL); err == nil {
						add(u.Hostname())
					}
				}
				add(a.Domain)
				add(a.IP)
			}
		}
	}
	for _, m := range reEvidenceHost.FindAllStringSubmatch(in.Evidence, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	return hosts
}

// matchTraffic 按 method + path 找最近一条平台记录；匹配不到返回 nil。
func (s *Store) matchTraffic(host, method, path string) *traffic.ExchangeMeta {
	if s.Traffic == nil || host == "" {
		return nil
	}
	metas, err := s.Traffic.Search(host, 0, 200)
	if err != nil {
		return nil
	}
	var best *traffic.ExchangeMeta
	for i := range metas {
		m := &metas[i]
		if !strings.EqualFold(m.Method, method) || !sameEvidencePath(exchangePath(m), path) {
			continue
		}
		if best == nil || m.TS > best.TS {
			best = m
		}
	}
	return best
}

// autoTrafficRefs 从 finding 的 evidence 文本里识别真实请求对象，并在平台的
// 流量库中按 method + host + path 匹配最近一条记录。这样即使模型忘了回填
// http_probe 返回的 traffic_id，报告/详情也能挂上可点击的原始报文。
// 显式写了 traffic_id 的证据优先直接采用；匹配不到就不绑定，绝不猜 ID。
func (s *Store) autoTrafficRefs(ctx context.Context, in db.RecordFindingInput) []db.TrafficRef {
	if s == nil || s.Traffic == nil || in.TaskID <= 0 {
		return nil
	}
	ev := strings.TrimSpace(in.Evidence)
	if ev == "" {
		return nil
	}
	var refs []db.TrafficRef
	seenID := map[string]bool{}
	for _, m := range reTrafficID.FindAllStringSubmatch(ev, -1) {
		id := strings.TrimSpace(m[1])
		if id == "" || seenID[id] {
			continue
		}
		seenID[id] = true
		refs = append(refs, db.TrafficRef{TrafficID: id, Role: "proof", Note: "自动关联：证据中显式引用的 traffic_id"})
		if len(refs) >= 5 {
			return refs
		}
	}
	if len(refs) > 0 {
		return refs
	}

	seen := map[string]bool{}
	// 证据里常见的写法是原始请求行（GET /api/x），不带 scheme；用 finding
	// 关联资产的 host 作为目标，再按 method+path 匹配。
	hosts := s.autoTargetHosts(in)
	for _, host := range hosts {
		for _, m := range reEvidenceRequestLine.FindAllStringSubmatch(ev, -1) {
			method := strings.ToUpper(m[1])
			path := m[2]
			key := method + " " + host + path
			if seen[key] {
				continue
			}
			seen[key] = true
			if best := s.matchTraffic(host, method, path); best != nil {
				refs = append(refs, db.TrafficRef{TrafficID: best.ID, Role: "proof", Note: "自动关联：证据中的请求行与平台记录匹配"})
			}
			if len(refs) >= 5 {
				return refs
			}
		}
	}

	for _, loc := range reEvidenceURL.FindAllStringIndex(ev, -1) {
		raw := strings.TrimRight(ev[loc[0]:loc[1]], ".,);]")
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		method := "GET"
		start := loc[0] - 300
		if start < 0 {
			start = 0
		}
		if m := reEvidenceMethod.FindStringSubmatch(ev[start:loc[0]]); len(m) > 1 {
			method = strings.ToUpper(m[1])
		}
		key := method + " " + u.Hostname() + u.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		if best := s.matchTraffic(u.Hostname(), method, u.EscapedPath()); best != nil {
			refs = append(refs, db.TrafficRef{TrafficID: best.ID, Role: "proof", Note: "自动关联：证据中的请求与平台记录匹配"})
		}
		if len(refs) >= 5 {
			break
		}
	}
	return refs
}

// exchangePath 兼容两种索引来源：被动代理会填 url_template，http_probe 的
// RecordEvidence 只填 url（path 列为空），所以按 url_template → path → URL 回退。
func exchangePath(m *traffic.ExchangeMeta) string {
	if m == nil {
		return ""
	}
	if m.URLTemplate != "" {
		return m.URLTemplate
	}
	if m.Path != "" {
		return m.Path
	}
	if u, err := url.Parse(m.URL); err == nil {
		return u.EscapedPath()
	}
	return ""
}

// sameEvidencePath 兼容 url_template 的 {id} 占位与证据里的具体路径。
func sameEvidencePath(a, b string) bool {
	if a == b {
		return true
	}
	if a == "" || b == "" {
		return false
	}
	if strings.HasSuffix(a, b) || strings.HasSuffix(b, a) {
		return true
	}
	if i := strings.IndexAny(a, "{<:"); i > 0 {
		return strings.HasPrefix(b, a[:i])
	}
	return false
}
