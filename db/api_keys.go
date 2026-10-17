// api_keys.go 持久 API Key:给 Hermes 等外部 agent 的长期凭据。
//
// 安全约定:
//   - 明文只在创建时返回一次,库里只存 SHA-256;
//   - token 形如 zrec_<64 hex>,用前缀快速识别,不误伤 JWT;
//   - scope=global 全平台;scope=project 只能访问绑定项目的任务/资产/漏洞/审批。
package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// APIKeyPrefix 是持久 key 的固定前缀(与 JWT 区分)。
const APIKeyPrefix = "zrec_"

// APIKey 是一条持久凭据的元数据(不含明文)。
type APIKey struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scope      string     `json:"scope"` // global|project
	ProjectID  *int64     `json:"project_id,omitempty"`
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

const apiKeyCols = `id, name, token_prefix, scope, project_id, enabled, expires_at, last_used_at, created_at`

func scanAPIKey(row interface{ Scan(...any) error }, k *APIKey) error {
	var pid sql.NullInt64
	var exp, used sql.NullTime
	if err := row.Scan(&k.ID, &k.Name, &k.Prefix, &k.Scope, &pid, &k.Enabled, &exp, &used, &k.CreatedAt); err != nil {
		return err
	}
	if pid.Valid {
		v := pid.Int64
		k.ProjectID = &v
	}
	if exp.Valid {
		v := exp.Time
		k.ExpiresAt = &v
	}
	if used.Valid {
		v := used.Time
		k.LastUsedAt = &v
	}
	return nil
}

func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

// CreateAPIKey 生成并入库一条持久 key,返回明文(仅此一次)。
func (d *DB) CreateAPIKey(name, scope string, projectID int64, expiresAt *time.Time) (string, *APIKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, fmt.Errorf("name 不能为空")
	}
	scope = strings.TrimSpace(scope)
	var pid any
	switch scope {
	case "global":
		projectID = 0
		pid = nil
	case "project":
		if projectID <= 0 {
			return "", nil, fmt.Errorf("项目级 key 必须指定 project_id")
		}
		pid = projectID
	default:
		return "", nil, fmt.Errorf("scope 必须是 global 或 project")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("生成 token 失败: %w", err)
	}
	raw := APIKeyPrefix + hex.EncodeToString(buf)
	prefix := raw[:len(APIKeyPrefix)+8]
	k := &APIKey{}
	err := scanAPIKey(d.QueryRow(`
INSERT INTO api_keys(name, token_prefix, token_hash, scope, project_id, expires_at)
VALUES ($1,$2,$3,$4,$5,$6)
RETURNING `+apiKeyCols,
		name, prefix, hashAPIKey(raw), scope, pid, expiresAt), k)
	if err != nil {
		return "", nil, err
	}
	return raw, k, nil
}

// ListAPIKeys returns all keys (metadata only), newest first.
func (d *DB) ListAPIKeys() ([]APIKey, error) {
	rows, err := d.Query(`SELECT ` + apiKeyCols + ` FROM api_keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := scanAPIKey(rows, &k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteAPIKey revokes a key (hard delete; the raw token cannot be recovered).
func (d *DB) DeleteAPIKey(id int64) error {
	_, err := d.Exec(`DELETE FROM api_keys WHERE id=$1`, id)
	return err
}

// AuthenticateAPIKey resolves a raw token to its metadata. Only enabled,
// non-expired keys pass; last_used_at is touched best-effort.
func (d *DB) AuthenticateAPIKey(raw string) (*APIKey, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, APIKeyPrefix) {
		return nil, false
	}
	var k APIKey
	err := scanAPIKey(d.QueryRow(`
SELECT `+apiKeyCols+` FROM api_keys
WHERE token_hash=$1 AND enabled
  AND (expires_at IS NULL OR expires_at > now())`, hashAPIKey(raw)), &k)
	if err != nil {
		return nil, false
	}
	_, _ = d.Exec(`UPDATE api_keys SET last_used_at=now() WHERE id=$1`, k.ID)
	return &k, true
}

// AssetsOutsideProject returns asset ids that belong to another project (or are
// stale). Used to enforce project-scoped API keys on batch operations.
func (d *DB) AssetsOutsideProject(ids []int64, projectID int64) ([]int64, error) {
	if len(ids) == 0 || projectID <= 0 {
		return nil, nil
	}
	rows, err := d.Query(`
SELECT id FROM assets
WHERE id = ANY($1::bigint[])
  AND project_id IS NOT NULL AND project_id <> $2`, ids, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// FindingTaskProjects maps finding id → owning task's project id (0 when the
// task is missing/unattached). Used to enforce project-scoped API keys.
func (d *DB) FindingTaskProjects(ids []int64) (map[int64]int64, error) {
	out := map[int64]int64{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := d.Query(`
SELECT f.id, COALESCE(t.project_id, 0)
FROM findings f
LEFT JOIN tasks t ON t.id = f.task_id
WHERE f.id = ANY($1::bigint[])`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, pid int64
		if err := rows.Scan(&id, &pid); err != nil {
			return nil, err
		}
		out[id] = pid
	}
	return out, rows.Err()
}
