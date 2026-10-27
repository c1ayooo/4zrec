// db.go implements read-only database credential verification: postgres via the
// pgx driver plus minimal read queries, redis via the raw RESP protocol (no
// driver dependency). mysql/mongodb/elasticsearch are not supported and return
// an explicit error rather than a fake success.
package cred

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// DBProbeInput is one database credential verification request.
type DBProbeInput struct {
	Type     string // postgres | redis(mysql/mongodb/elasticsearch unsupported)
	Host     string
	Port     int // 0 = default port
	Username string
	Password string
	Database string // postgres optional
	Timeout  time.Duration
}

// DBProbeResult is the live-connection conclusion: liveness + permission surface.
type DBProbeResult struct {
	Alive    bool   `json:"alive"`
	Authed   bool   `json:"authed"`   // redis: AUTH result
	User     string `json:"user"`     // current user (postgres)
	Version  string `json:"version"`  // server version
	Database string `json:"database"` // connected database
	Detail   string `json:"detail"`   // human-readable conclusion
}

// DefaultDBPort returns the default port for a database type.
func DefaultDBPort(typ string) int {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "postgres", "postgresql":
		return 5432
	case "redis":
		return 6379
	case "mysql":
		return 3306
	case "mongodb":
		return 27017
	case "elasticsearch":
		return 9200
	}
	return 0
}

// VerifyDB performs live verification. Invalid credentials / unreachable network
// return an explicit Detail, never a fake success.
func VerifyDB(ctx context.Context, in DBProbeInput) (*DBProbeResult, error) {
	typ := strings.ToLower(strings.TrimSpace(in.Type))
	if in.Port <= 0 {
		in.Port = DefaultDBPort(typ)
	}
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch typ {
	case "postgres", "postgresql":
		return verifyPostgres(ctx, in)
	case "redis":
		return verifyRedis(ctx, in)
	case "mysql", "mongodb", "elasticsearch":
		return nil, fmt.Errorf("%s 实连验证暂未支持(内核未引入对应驱动);请用 mysql/redis-cli 等客户端经 Bash 验证", typ)
	default:
		return nil, fmt.Errorf("不支持的数据库类型 %q(postgres/redis)", typ)
	}
}

func verifyPostgres(ctx context.Context, in DBProbeInput) (*DBProbeResult, error) {
	db := in.Database
	if db == "" {
		db = "postgres"
	}
	var auth strings.Builder
	if in.Username != "" {
		fmt.Fprintf(&auth, " user=%s", in.Username)
	}
	if in.Password != "" {
		fmt.Fprintf(&auth, " password=%s", in.Password)
	}
	dsn := fmt.Sprintf("host=%s port=%d%s dbname=%s sslmode=disable connect_timeout=8",
		in.Host, in.Port, auth.String(), db)
	handle, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("驱动初始化失败: %w", err)
	}
	defer handle.Close()
	if err := handle.PingContext(ctx); err != nil {
		return &DBProbeResult{Alive: true, Detail: fmt.Sprintf("连接失败(凭据无效或库不存在): %v", err)}, nil
	}
	var user, version string
	_ = handle.QueryRowContext(ctx, `SELECT current_user, current_setting('server_version')`).Scan(&user, &version)
	var canCreate, isSuper bool
	_ = handle.QueryRowContext(ctx, `SELECT rolcreatedb, rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&canCreate, &isSuper)
	detail := fmt.Sprintf("连接成功:用户 %s@%s/%s,PG %s", user, in.Host, db, version)
	if isSuper {
		detail += ",超级用户(rolsuper)"
	} else if canCreate {
		detail += ",可建库(rolcreatedb)"
	}
	return &DBProbeResult{Alive: true, Authed: true, User: user, Version: version, Database: db, Detail: detail}, nil
}

// verifyRedis speaks raw RESP: PING/AUTH/INFO server.
func verifyRedis(ctx context.Context, in DBProbeInput) (*DBProbeResult, error) {
	addr := net.JoinHostPort(in.Host, strconv.Itoa(in.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &DBProbeResult{Alive: false, Detail: fmt.Sprintf("端口不通: %v", err)}, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	send := func(cmd ...string) (string, error) {
		var b strings.Builder
		fmt.Fprintf(&b, "*%d\r\n", len(cmd))
		for _, c := range cmd {
			fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(c), c)
		}
		if _, err := conn.Write([]byte(b.String())); err != nil {
			return "", err
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return "", fmt.Errorf("读取响应失败: %v", err)
		}
		return string(buf[:n]), nil
	}
	// With a password, AUTH first (empty username = single-password mode).
	// Without a password, "authed" must start false: the target may have
	// requirepass enabled and return -NOAUTH, which is not auth success.
	authed := false
	if in.Password != "" {
		authCmd := []string{"AUTH", in.Password}
		if in.Username != "" {
			authCmd = []string{"AUTH", in.Username, in.Password}
		}
		resp, err := send(authCmd...)
		if err != nil {
			return &DBProbeResult{Alive: true, Detail: "协议交互失败: " + err.Error()}, nil
		}
		if !strings.HasPrefix(resp, "+OK") {
			return &DBProbeResult{Alive: true, Authed: false, Detail: "AUTH 失败(密码无效): " + strings.TrimSpace(resp)}, nil
		}
		authed = true
	}
	pong, err := send("PING")
	if err != nil || !strings.HasPrefix(pong, "+PONG") {
		return &DBProbeResult{Alive: true, Authed: false, Detail: "PING 异常: " + strings.TrimSpace(pong)}, nil
	}
	// PING success = current credential (including "no password") can execute
	// commands. No password + reachable means the instance is unauthenticated.
	authed = true
	info, _ := send("INFO", "server")
	version := ""
	for _, line := range strings.Split(info, "\n") {
		if v := strings.TrimPrefix(strings.TrimSpace(line), "redis_version:"); v != strings.TrimSpace(line) {
			version = v
		}
	}
	return &DBProbeResult{Alive: true, Authed: authed, Version: version,
		Detail: fmt.Sprintf("连接成功:Redis %s @%s%s", version, addr, passwordNote(in.Password))}, nil
}

func passwordNote(pw string) string {
	if pw == "" {
		return "(无密码,未授权访问!)"
	}
	return ""
}
