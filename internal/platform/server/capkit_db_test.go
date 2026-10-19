package server

import (
	"context"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/c1ayooo/capkit/core"
)

func TestDBWriteStatementClassification(t *testing.T) {
	cases := []struct {
		stmt string
		want string // "" = read
	}{
		{"SELECT * FROM users", ""},
		{"  select 1", ""},
		{"SHOW TABLES", ""},
		{"WITH t AS (SELECT 1) SELECT * FROM t", "with"},
		{"INSERT INTO t VALUES (1)", "insert"},
		{"delete from t where id=1", "delete"},
		{"UPDATE t SET a=1", "update"},
		{"DROP TABLE t", "drop"},
		{"ALTER TABLE t ADD c int", "alter"},
		{"TRUNCATE t", "truncate"},
		{"GRANT ALL ON *.* TO 'x'@'%'", "grant"},
		{"create table t (id int)", "create"},
		{"CALL some_proc()", "call"},
		{"WITH x AS (SELECT 1) DELETE FROM t", "with"},
	}
	for _, c := range cases {
		if got := writeKind(c.stmt); got != c.want {
			t.Fatalf("writeKind(%q) = %q, want %q", c.stmt, got, c.want)
		}
	}
}

func TestClipCellFlattensAndTruncates(t *testing.T) {
	if got := clipCell("a\nb\tc"); got != `a\nb\tc` {
		t.Fatalf("换行/制表符未转义: %q", got)
	}
	long := strings.Repeat("x", dbMaxCell+10)
	got := clipCell(long)
	if len([]rune(got)) != dbMaxCell+1 { // +1 for the ellipsis
		t.Fatalf("超长单元格未按 %d 截断: %d", dbMaxCell, len(got))
	}
}

func TestMySQLDSNRoundTripsCredentials(t *testing.T) {
	spec := core.SessionSpec{Host: "10.0.0.5", User: "root", Secret: "p@ss:word/x"}
	dsn := mysqlDSN(spec, "app")
	if !strings.Contains(dsn, "3306") {
		t.Fatalf("未使用默认端口: %s", dsn)
	}
	// A DSN carries the password by design; what matters is that the driver
	// parses it back byte-for-byte, so a password with reserved characters
	// cannot silently become a different one.
	parsed, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("DSN 不可解析: %v", err)
	}
	if parsed.Passwd != spec.Secret || parsed.User != spec.User || parsed.DBName != "app" {
		t.Fatalf("凭据往返不一致: user=%q pass=%q db=%q", parsed.User, parsed.Passwd, parsed.DBName)
	}
}

func TestPostgresDSNDefaultsAndOverrides(t *testing.T) {
	spec := core.SessionSpec{Host: "10.0.0.5", User: "postgres", Secret: "p@ss word"}
	dsn := postgresDSN(spec, "app")
	if !strings.Contains(dsn, "sslmode=disable") {
		t.Fatalf("默认应 disable sslmode: %s", dsn)
	}
	if strings.Contains(dsn, "p@ss word") {
		t.Fatalf("DSN 里出现明文口令: %s", dsn)
	}
	spec.Options = map[string]string{"sslmode": "require"}
	spec.Port = 15432
	if dsn := postgresDSN(spec, "app"); !strings.Contains(dsn, "sslmode=require") || !strings.Contains(dsn, "15432") {
		t.Fatalf("sslmode/端口覆盖未生效: %s", dsn)
	}
}

func TestDBOpenerValidatesInput(t *testing.T) {
	opener := dbOpeners()["mysql"]
	ctx := context.Background()
	if _, err := opener.Open(ctx, core.SessionSpec{Kind: "mysql"}); err == nil {
		t.Fatalf("缺 host 应报错")
	}
	if _, err := opener.Open(ctx, core.SessionSpec{Kind: "mysql", Host: "127.0.0.1"}); err == nil {
		t.Fatalf("缺库名应报错")
	}
}

func TestDBOpenerReportsUnreachableTarget(t *testing.T) {
	// Port 1 has nothing listening: the failure must be a target error the
	// agent can retry elsewhere, not an invalid-input one.
	_, err := dbOpeners()["mysql"].Open(context.Background(), core.SessionSpec{
		Kind: "mysql", Host: "127.0.0.1", Port: 1, User: "root", Secret: "x",
		Options: map[string]string{"database": "app"},
	})
	if err == nil {
		t.Fatalf("不可达目标应报错")
	}
	if !strings.Contains(err.Error(), "连接失败") {
		t.Fatalf("错误应说明是连接失败: %v", err)
	}
	if strings.Contains(err.Error(), "x") && strings.Contains(err.Error(), "root:x") {
		t.Fatalf("错误里不应出现凭据: %v", err)
	}
}

func TestDBKindCatalogCoversBothDialects(t *testing.T) {
	openers := dbOpeners()
	for _, kind := range []string{"mysql", "postgres"} {
		if _, ok := openers[kind]; !ok {
			t.Fatalf("缺少 %s opener", kind)
		}
	}
}
