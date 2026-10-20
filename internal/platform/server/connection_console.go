// connection_console.go 连接台账的图形化控制台（手工操作）:对台账里的 SSH/DB/
// WebShell 凭据直接在页面执行命令/查询——SSH 命令执行(x/crypto/ssh 一次性 exec)、
// SQL 制台(pgx / go-sql-driver)、redis 命令制台(裸 RESP,与 creds 探针同协议)、
// WebShell 命令执行(plain 协议一次性请求)。
// 手工操作由操作者驱动(auth 后可用),执行结果回写台账 status/last_checked_at。
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// connByID 取台账行。
func (s *Server) connByID(ctx context.Context, id int64) (*db.Connection, error) {
	rows, err := s.m.pg.ListConnections(ctx, 0, "", 500)
	if err != nil {
		return nil, err
	}
	for _, c := range rows {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, fmt.Errorf("连接 #%d 不存在", id)
}

// ---------- SSH 命令执行 ----------

func (s *Server) connSSHExec(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct {
		Command string `json:"command"`
		Timeout int    `json:"timeout_seconds"`
	}
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Command) == "" {
		writeErr(w, 400, "command 必填")
		return
	}
	c, err := s.connByID(r.Context(), id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if c.Kind != "ssh" {
		writeErr(w, 400, "该连接不是 SSH 类型")
		return
	}
	timeout := time.Duration(in.Timeout) * time.Second
	if timeout <= 0 || timeout > 300 {
		timeout = 60 * time.Second
	}
	start := time.Now()
	out, execErr := sshExecOnce(r.Context(), c, in.Command, timeout)
	elapsed := time.Since(start).Milliseconds()
	if execErr != nil {
		_ = pg.UpdateConnectionStatus(r.Context(), id, "dead")
		writeJSON(w, 200, map[string]any{"ok": false, "error": execErr.Error(), "elapsed_ms": elapsed})
		return
	}
	_ = pg.UpdateConnectionStatus(r.Context(), id, "alive")
	writeJSON(w, 200, map[string]any{"ok": true, "output": out, "elapsed_ms": elapsed})
}

// dialSSHClient 建连+认证(密码或私钥,10s 超时);exec 与终端共用。
func dialSSHClient(ctx context.Context, c *db.Connection) (*ssh.Client, error) {
	var auth []ssh.AuthMethod
	if strings.Contains(c.Secret, "PRIVATE KEY") {
		key, err := ssh.ParsePrivateKey([]byte(c.Secret))
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %v", err)
		}
		auth = append(auth, ssh.PublicKeys(key))
	} else if c.Secret != "" {
		auth = append(auth, ssh.Password(c.Secret))
	} else {
		return nil, fmt.Errorf("该连接没有可用的口令/私钥")
	}
	port := c.Port
	if port <= 0 {
		port = 22
	}
	cfg := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("端口不通: %v", err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH 认证失败或握手异常: %v", err)
	}
	// client.Close 会关掉底层 conn。
	return ssh.NewClient(sc, chans, reqs), nil
}

// sshExecOnce 一次性 SSH 命令执行(密码或私钥,10s 建连超时)。
func sshExecOnce(ctx context.Context, c *db.Connection, command string, timeout time.Duration) (string, error) {
	client, err := dialSSHClient(ctx, c)
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	type res struct {
		out []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		o, e := sess.CombinedOutput(command)
		ch <- res{o, e}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-ch:
		// 有输出时即便 exit≠0 也回传(命令确实执行了)。
		if r.err != nil && len(r.out) == 0 {
			return "", r.err
		}
		text := string(r.out)
		if r.err != nil {
			text += "\n[exit: " + r.err.Error() + "]"
		}
		return text, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("命令执行超时(%s)", timeout)
	}
}

// ---------- DB 制台 ----------

func (s *Server) connDBQuery(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct {
		Query string `json:"query"`
	}
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Query) == "" {
		writeErr(w, 400, "query 必填")
		return
	}
	c, err := s.connByID(r.Context(), id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	start := time.Now()
	switch c.Kind {
	case "postgres":
		cols, rows, qerr := sqlConsole(ctx, "pgx", pgConsoleDSN(c), c, in.Query)
		elapsed := time.Since(start).Milliseconds()
		if qerr != nil {
			_ = pg.UpdateConnectionStatus(r.Context(), id, "dead")
			writeJSON(w, 200, map[string]any{"ok": false, "error": qerr.Error(), "elapsed_ms": elapsed})
			return
		}
		_ = pg.UpdateConnectionStatus(r.Context(), id, "alive")
		writeJSON(w, 200, map[string]any{"ok": true, "columns": cols, "rows": rows, "elapsed_ms": elapsed})
	case "mysql":
		// 与 postgres 的差别只在驱动和 DSN,取结果的表格化逻辑共用一套。
		cols, rows, qerr := sqlConsole(ctx, "mysql", mysqlConsoleDSN(c), c, in.Query)
		elapsed := time.Since(start).Milliseconds()
		if qerr != nil {
			_ = pg.UpdateConnectionStatus(r.Context(), id, "dead")
			writeJSON(w, 200, map[string]any{"ok": false, "error": qerr.Error(), "elapsed_ms": elapsed})
			return
		}
		_ = pg.UpdateConnectionStatus(r.Context(), id, "alive")
		writeJSON(w, 200, map[string]any{"ok": true, "columns": cols, "rows": rows, "elapsed_ms": elapsed})
	case "webshell":
		out, qerr := webshellConsole(ctx, c, in.Query)
		elapsed := time.Since(start).Milliseconds()
		if qerr != nil {
			_ = pg.UpdateConnectionStatus(r.Context(), id, "dead")
			writeJSON(w, 200, map[string]any{"ok": false, "error": qerr.Error(), "elapsed_ms": elapsed})
			return
		}
		_ = pg.UpdateConnectionStatus(r.Context(), id, "alive")
		writeJSON(w, 200, map[string]any{"ok": true, "output": out, "elapsed_ms": elapsed})
	case "redis":
		out, qerr := redisConsole(ctx, c, in.Query)
		elapsed := time.Since(start).Milliseconds()
		if qerr != nil {
			_ = pg.UpdateConnectionStatus(r.Context(), id, "dead")
			writeJSON(w, 200, map[string]any{"ok": false, "error": qerr.Error(), "elapsed_ms": elapsed})
			return
		}
		_ = pg.UpdateConnectionStatus(r.Context(), id, "alive")
		writeJSON(w, 200, map[string]any{"ok": true, "output": out, "elapsed_ms": elapsed})
	default:
		writeErr(w, 400, fmt.Sprintf("该连接的控制台暂未支持(%s);已支持 ssh/postgres/mysql/redis/webshell", c.Kind))
	}
}

// sqlConsole 是 SQL 控制台的公用实现:任意语句,查询类返回表格,其余返回
// 影响行数。driver 是 database/sql 的驱动名,dsn 由各方言的构造函数给出。
func sqlConsole(ctx context.Context, driver, dsn string, c *db.Connection, query string) ([]string, [][]string, error) {
	h, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, nil, err
	}
	defer h.Close()
	if isQueryLike(query) {
		rows, err := h.QueryContext(ctx, query)
		if err != nil {
			return nil, nil, err
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var out [][]string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return nil, nil, err
			}
			line := make([]string, len(cols))
			for i, v := range vals {
				line[i] = formatCell(v)
			}
			out = append(out, line)
			if len(out) >= 500 {
				break
			}
		}
		return cols, out, rows.Err()
	}
	res, err := h.ExecContext(ctx, query)
	if err != nil {
		return nil, nil, err
	}
	n, _ := res.RowsAffected()
	return []string{"affected_rows"}, [][]string{{strconv.FormatInt(n, 10)}}, nil
}

// pgConsoleDSN postgres 制台连接串。
func pgConsoleDSN(c *db.Connection) string {
	dbname := connectionDatabase(c, "postgres")
	port := c.Port
	if port <= 0 {
		port = 5432
	}
	var auth strings.Builder
	if c.Username != "" {
		fmt.Fprintf(&auth, " user=%s", c.Username)
	}
	if c.Secret != "" {
		fmt.Fprintf(&auth, " password=%s", c.Secret)
	}
	return fmt.Sprintf("host=%s port=%d%s dbname=%s sslmode=disable connect_timeout=8",
		c.Host, port, auth.String(), dbname)
}

// mysqlConsoleDSN mysql 制台连接串。口令里可能带 @ : / 等字符,交给驱动自己的
// 配置格式化器转义,不手工拼串。
func mysqlConsoleDSN(c *db.Connection) string {
	cfg := mysqldriver.NewConfig()
	cfg.User = c.Username
	cfg.Passwd = c.Secret
	cfg.Net = "tcp"
	port := c.Port
	if port <= 0 {
		port = 3306
	}
	cfg.Addr = net.JoinHostPort(c.Host, strconv.Itoa(port))
	cfg.DBName = connectionDatabase(c, "")
	cfg.Timeout = 8 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.AllowNativePasswords = true
	return cfg.FormatDSN()
}

// connectionDatabase 取台账行里登记的库名。
func connectionDatabase(c *db.Connection, def string) string {
	var extra struct {
		Database string `json:"database"`
	}
	_ = jsonUnmarshalSafe(c.Extra, &extra)
	if dbname := strings.TrimSpace(extra.Database); dbname != "" {
		return dbname
	}
	return def
}

// webshellConsole WebShell 控制台:按台账里登记的协议发一次命令请求。
// 与 SSH/DB 控制台一样是"一次性执行",不建立常驻会话;需要持续操作请用终端
// (会话带证据与项目归属)。
func webshellConsole(ctx context.Context, c *db.Connection, command string) (string, error) {
	conf := webshellConfigOf(c)
	if conf.URL == "" {
		return "", fmt.Errorf("该 WebShell 连接没填 URL(extra.url)")
	}
	return execWebShellOnce(ctx, conf, command)
}

// connWebShellExec WebShell 控制台入口:POST /api/connections/{id}/webshell/exec。
func (s *Server) connWebShellExec(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in struct {
		Command string `json:"command"`
	}
	if err := decode(r, &in); err != nil || strings.TrimSpace(in.Command) == "" {
		writeErr(w, 400, "command 必填")
		return
	}
	c, err := s.connByID(r.Context(), id)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	if c.Kind != "webshell" {
		writeErr(w, 400, "该连接不是 WebShell 类型")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	start := time.Now()
	out, execErr := webshellConsole(ctx, c, in.Command)
	elapsed := time.Since(start).Milliseconds()
	if execErr != nil {
		// 口令错(403)与落点失效都说明这条凭据/落点不可用,如实回写状态。
		_ = pg.UpdateConnectionStatus(r.Context(), id, "dead")
		writeJSON(w, 200, map[string]any{"ok": false, "error": execErr.Error(), "elapsed_ms": elapsed})
		return
	}
	_ = pg.UpdateConnectionStatus(r.Context(), id, "alive")
	writeJSON(w, 200, map[string]any{"ok": true, "output": out, "elapsed_ms": elapsed})
}

func isQueryLike(q string) bool {
	u := strings.ToUpper(strings.TrimSpace(q))
	for _, p := range []string{"SELECT", "SHOW", "EXPLAIN", "WITH", "TABLE ", "VALUES"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func formatCell(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(t)
	case time.Time:
		return t.Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// redisConsole 裸 RESP 制台:整行作为一条命令(空格分词),返回原始回复文本。
func redisConsole(ctx context.Context, c *db.Connection, line string) (string, error) {
	port := c.Port
	if port <= 0 {
		port = 6379
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("端口不通: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	send := func(parts []string) (string, error) {
		var b strings.Builder
		fmt.Fprintf(&b, "*%d\r\n", len(parts))
		for _, p := range parts {
			fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
		}
		if _, err := conn.Write([]byte(b.String())); err != nil {
			return "", err
		}
		buf := make([]byte, 64<<10)
		n, err := conn.Read(buf)
		if err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	}
	if c.Secret != "" {
		auth := []string{"AUTH", c.Secret}
		if c.Username != "" {
			auth = []string{"AUTH", c.Username, c.Secret}
		}
		resp, err := send(auth)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(resp, "+OK") {
			return "", fmt.Errorf("AUTH 失败: %s", strings.TrimSpace(resp))
		}
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) == 0 {
		return "", fmt.Errorf("空命令")
	}
	return send(parts)
}

func jsonUnmarshalSafe(raw []byte, out any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}
