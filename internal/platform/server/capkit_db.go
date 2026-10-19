package server

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/capkit/core"
	mysqldriver "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver for sql.Open("pgx", ...)
)

// Database sessions.
//
// capkit's sessionkit covers network transports (SSH/WinRM/SMB) and stops
// there; a database is another kind of foothold with the same shape — connect
// with credentials, run one statement, read the result, close — so it plugs
// into the same Session contract instead of growing a parallel tool family.
//
// Semantics differ from a shell in two ways the user must see:
//   - "command" is one SQL statement, not a shell command line;
//   - the driver must be told where to connect, so the statement never carries
//     a USE/connect prefix.
//
// Credentials are never logged: the DSN is built in memory, the manager stores
// only the session info (host/port/user/database), and errors from the drivers
// do not echo the DSN.

const (
	// dbMaxRows bounds the result set turned into text. Pentest queries are
	// usually targeted; a full table dump belongs in session_download, and an
	// unbounded format loop would hang the console.
	dbMaxRows = 200
	// dbMaxCell bounds one cell so a BLOB cannot flood the terminal.
	dbMaxCell = 512
	// dbDefaultTimeout bounds one statement.
	dbDefaultTimeout = 30 * time.Second
)

// dbOpener builds a Session for one SQL driver. Driver is the database/sql
// driver name; Kind is what session_open receives ("mysql", "postgres").
type dbOpener struct {
	Kind   string
	Driver string
	// DefaultPort is used when the session spec carries none.
	DefaultPort int
	// DSN builds a connection string. Kept as a field so a new dialect is one
	// function, not a new type.
	DSN func(spec core.SessionSpec, dbName string) string
}

// Open connects and pings, so a wrong password fails here rather than on the
// first statement. The database name rides in Options["database"] because a
// database is part of the target, not of the statement.
func (o *dbOpener) Open(ctx context.Context, spec core.SessionSpec) (core.Session, error) {
	host := strings.TrimSpace(spec.Host)
	if host == "" {
		return nil, core.InvalidInput("数据库会话需要 host")
	}
	port := spec.Port
	if port == 0 {
		port = o.DefaultPort
	}
	dbName := strings.TrimSpace(spec.Options["database"])
	if dbName == "" {
		return nil, core.InvalidInput("数据库会话需要 options.database（库名）")
	}
	db, err := sql.Open(o.Driver, o.DSN(spec, dbName))
	if err != nil {
		// sql.Open only validates the DSN; the error cannot contain the
		// password for either driver, but keep the message generic anyway.
		return nil, core.InvalidInput(o.Kind + " 连接参数无效: " + err.Error())
	}
	// One connection per session: a session models a foothold, and pooling
	// would hide which connection a statement ran on.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = dbDefaultTimeout
	}
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, core.TargetUnreachable(o.Kind + " 连接失败: " + err.Error())
	}

	proto := spec.Options["protocol"]
	return &dbSession{
		db: db, kind: o.Kind, timeout: timeout, proto: proto,
		info: core.SessionInfo{
			Kind: o.Kind, Host: host, Port: port, User: spec.User,
			Labels: spec.Labels,
			Meta:   map[string]string{"database": dbName},
		},
	}, nil
}

// dbSession is one SQL foothold. Statements are serialized by the single
// connection, so no extra lock is needed.
type dbSession struct {
	db      *sql.DB
	kind    string
	timeout time.Duration
	proto   string
	info    core.SessionInfo
}

func (s *dbSession) Info() core.SessionInfo { return s.info }

func (s *dbSession) Close() error { return s.db.Close() }

// Exec runs one statement. Statements that return rows are rendered as a TSV
// table with a header; the rest report the affected-row count. Write
// statements are labelled in the output so the operator sees what just ran.
func (s *dbSession) Exec(ctx context.Context, cmd string, opts core.ExecOpts) (core.Output, error) {
	statement := strings.TrimSpace(cmd)
	if statement == "" {
		return core.Output{}, core.InvalidInput("SQL 语句为空")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = s.timeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	rows, err := s.db.QueryContext(runCtx, statement)
	if err != nil {
		// A driver error carries the server's message, not the DSN:
		// exec failures are reported as stdout-less output with a non-zero
		// exit code, matching how a shell reports a failed command.
		return core.OutputFor(statement, "", err.Error(), 1, time.Since(started), opts.MaxOutput), nil
	}
	text, truncated, err := formatRows(rows)
	if err != nil {
		return core.OutputFor(statement, "", err.Error(), 1, time.Since(started), opts.MaxOutput), nil
	}
	prefix := ""
	if isWriteStatement(statement) {
		prefix = "-- 写操作：" + writeKind(statement) + "\n"
	}
	out := core.OutputFor(statement, prefix+text, "", 0, time.Since(started), opts.MaxOutput)
	out.Truncated = out.Truncated || truncated
	return out, nil
}

// formatRows renders a result set as TSV. Column values are read as raw bytes
// so driver-specific types (numeric, timestamp, JSON) print the way the server
// sent them rather than through a lossy Go conversion.
func formatRows(rows *sql.Rows) (string, bool, error) {
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return "", false, err
	}
	var b strings.Builder
	b.WriteString(strings.Join(cols, "\t"))
	b.WriteString("\n")
	scanned := make([]any, len(cols))
	holders := make([]sql.RawBytes, len(cols))
	for i := range holders {
		scanned[i] = &holders[i]
	}
	truncated := false
	count := 0
	for rows.Next() {
		if count >= dbMaxRows {
			truncated = true
			break
		}
		if err := rows.Scan(scanned...); err != nil {
			return b.String(), truncated, err
		}
		cells := make([]string, len(holders))
		for i, h := range holders {
			cells[i] = clipCell(string(h))
		}
		b.WriteString(strings.Join(cells, "\t"))
		b.WriteString("\n")
		count++
	}
	if err := rows.Err(); err != nil {
		return b.String(), truncated, err
	}
	b.WriteString(fmt.Sprintf("-- %d 行", count))
	if truncated {
		b.WriteString(fmt.Sprintf("（已截断，上限 %d 行）", dbMaxRows))
	}
	b.WriteString("\n")
	return b.String(), truncated, nil
}

// clipCell keeps one cell printable on a single line and bounded in size.
func clipCell(v string) string {
	v = strings.ReplaceAll(v, "\n", "\\n")
	v = strings.ReplaceAll(v, "\t", "\\t")
	if len(v) > dbMaxCell {
		return v[:dbMaxCell] + "…"
	}
	return v
}

// writeVerbs are the statement heads that change data or schema. The list errs
// toward flagging: a false positive is a comment line, a false negative is a
// destructive statement that ran unlabelled.
var writeVerbs = []string{
	"insert", "update", "delete", "replace", "merge", "upsert",
	"create", "alter", "drop", "truncate", "rename",
	"grant", "revoke", "comment",
	"call", "exec", "execute", "copy", "load", "set", "lock", "unlock",
}

// isWriteStatement reports whether a statement changes data or schema.
func isWriteStatement(statement string) bool {
	_, ok := writeKindOK(statement)
	return ok
}

// writeKind returns the verb that made a statement a write, for the label.
func writeKind(statement string) string {
	verb, _ := writeKindOK(statement)
	return verb
}

func writeKindOK(statement string) (string, bool) {
	head := strings.ToLower(strings.TrimLeft(statement, " \t\r\n("))
	if strings.HasPrefix(head, "with ") {
		// A CTE can carry INSERT/UPDATE/DELETE after its definitions, and
		// telling those apart needs a real parser. Flag every WITH: the cost is
		// one comment line, the alternative is an unlabelled destructive
		// statement.
		return "with", true
	}
	for _, verb := range writeVerbs {
		if strings.HasPrefix(head, verb+" ") || head == verb {
			return verb, true
		}
	}
	return "", false
}

// mysqlDSN builds a DSN through the driver's own config formatter, so field
// escaping is the driver's business. The DSN holds the password by design; it
// lives only in this call and in database/sql's pool, and is never logged.
func mysqlDSN(spec core.SessionSpec, dbName string) string {
	cfg := mysqldriver.NewConfig()
	cfg.User = spec.User
	cfg.Passwd = spec.Secret
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(spec.Host, strconv.Itoa(portOf(spec, 3306)))
	cfg.DBName = dbName
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = dbDefaultTimeout
	cfg.AllowNativePasswords = true
	if tls := spec.Options["tls"]; tls != "" {
		cfg.TLSConfig = tls
	}
	return cfg.FormatDSN()
}

// postgresDSN builds a URL DSN; url.URL escapes the password for us. sslmode
// defaults to disable because pentest targets rarely have valid certs, and a
// silent TLS failure reads as "wrong password" to the operator.
func postgresDSN(spec core.SessionSpec, dbName string) string {
	sslmode := spec.Options["sslmode"]
	if sslmode == "" {
		sslmode = "disable"
	}
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(spec.User, spec.Secret),
		Host:   net.JoinHostPort(spec.Host, strconv.Itoa(portOf(spec, 5432))),
		Path:   "/" + dbName,
	}
	q := url.Values{}
	q.Set("sslmode", sslmode)
	q.Set("connect_timeout", "10")
	u.RawQuery = q.Encode()
	return u.String()
}

func portOf(spec core.SessionSpec, def int) int {
	if spec.Port > 0 {
		return spec.Port
	}
	return def
}

// dbOpeners is the map the bridge registers: kind → opener.
func dbOpeners() map[string]core.SessionOpener {
	return map[string]core.SessionOpener{
		"mysql":    &dbOpener{Kind: "mysql", Driver: "mysql", DefaultPort: 3306, DSN: mysqlDSN},
		"postgres": &dbOpener{Kind: "postgres", Driver: "pgx", DefaultPort: 5432, DSN: postgresDSN},
	}
}
