// connections.go 连接台账 CRUD:SSH/数据库/协议凭据统一存储(明文,不做 vault——
// 用户口径)。必须绑定项目;同项目同 kind 同 host:port 同用户唯一(重录合并
// secret/extra/note)。source=discovered 为 worker 任务中自动落库。
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Connection 一行连接台账。
type Connection struct {
	ID            int64           `json:"id"`
	ProjectID     int64           `json:"project_id"`
	ProjectName   string          `json:"project_name,omitempty"`
	Kind          string          `json:"kind"`
	Host          string          `json:"host"`
	Port          int             `json:"port"`
	Username      string          `json:"username"`
	Secret        string          `json:"secret"`
	Extra         json.RawMessage `json:"extra"`
	Source        string          `json:"source"`
	Status        string          `json:"status"`
	LastCheckedAt *time.Time      `json:"last_checked_at,omitempty"`
	Note          string          `json:"note"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

const connectionCols = `c.id, c.project_id, COALESCE(p.name,''), c.kind, c.host, c.port, c.username,
	c.secret, c.extra, c.source, c.status, c.last_checked_at, c.note, c.created_at, c.updated_at`

// UpsertConnection 幂等入库:同键重录合并(secret 非空才覆盖、extra/note 非空才覆盖、
// source 升级为 discovered 时不降级为 manual)。返回行 id 与是否新建。
func (d *DB) UpsertConnection(ctx context.Context, c *Connection) (int64, bool, error) {
	if c.Extra == nil {
		c.Extra = json.RawMessage("{}")
	}
	var id int64
	var created bool
	err := d.QueryRowContext(ctx, `
INSERT INTO connections(project_id, kind, host, port, username, secret, extra, source, status, note)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (project_id, kind, host, port, username) DO UPDATE SET
  secret  = CASE WHEN EXCLUDED.secret <> '' THEN EXCLUDED.secret ELSE connections.secret END,
  extra   = CASE WHEN EXCLUDED.extra <> '{}'::jsonb THEN EXCLUDED.extra ELSE connections.extra END,
  note    = CASE WHEN EXCLUDED.note <> '' THEN EXCLUDED.note ELSE connections.note END,
  source  = CASE WHEN connections.source = 'manual' AND EXCLUDED.source = 'discovered' THEN 'manual' ELSE EXCLUDED.source END,
  status  = CASE WHEN EXCLUDED.status <> 'unknown' THEN EXCLUDED.status ELSE connections.status END,
  updated_at = now()
RETURNING id, (xmax = 0) AS inserted`,
		c.ProjectID, c.Kind, c.Host, c.Port, c.Username, c.Secret, c.Extra, c.Source, c.Status, c.Note).
		Scan(&id, &created)
	return id, created, err
}

// ListConnections 台账列表;projectID>0 过滤、kind 空=全部。
func (d *DB) ListConnections(ctx context.Context, projectID int64, kind string, limit int) ([]*Connection, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	where := "TRUE"
	args := []any{}
	if projectID > 0 {
		args = append(args, projectID)
		where += " AND " + fmt.Sprintf("c.project_id=$%d", len(args))
	}
	if kind != "" {
		args = append(args, kind)
		where += " AND " + fmt.Sprintf("c.kind=$%d", len(args))
	}
	args = append(args, limit)
	rows, err := d.QueryContext(ctx, `
SELECT `+connectionCols+` FROM connections c LEFT JOIN projects p ON p.id=c.project_id
WHERE `+where+fmt.Sprintf(" ORDER BY c.updated_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Connection{}
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.ProjectName, &c.Kind, &c.Host, &c.Port, &c.Username,
			&c.Secret, &c.Extra, &c.Source, &c.Status, &c.LastCheckedAt, &c.Note, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// UpdateConnectionStatus 探活结果回写。
func (d *DB) UpdateConnectionStatus(ctx context.Context, id int64, status string) error {
	_, err := d.ExecContext(ctx, `UPDATE connections SET status=$2, last_checked_at=now(), updated_at=now() WHERE id=$1`, id, status)
	return err
}

// DeleteConnection 删除。
func (d *DB) DeleteConnection(ctx context.Context, id int64) error {
	_, err := d.ExecContext(ctx, `DELETE FROM connections WHERE id=$1`, id)
	return err
}

func i64Placeholder(args []any, prefix string) string {
	return fmt.Sprintf("%s$%d", prefix, len(args))
}

// DefaultConnectionPort 类型默认端口(与 creds.DefaultDBPort 对齐 + 协议族扩展)。
func DefaultConnectionPort(kind string) int {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "ssh":
		return 22
	case "postgres", "postgresql":
		return 5432
	case "mysql":
		return 3306
	case "redis":
		return 6379
	case "mongodb":
		return 27017
	case "elasticsearch":
		return 9200
	case "smb":
		return 445
	case "winrm":
		return 5985
	case "ldap":
		return 389
	case "vnc":
		return 5900
	case "ftp":
		return 21
	case "proxy":
		return 1080
	}
	return 0
}
