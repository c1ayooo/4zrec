package db

import (
	"strings"
	"testing"
)

// 测试二进制里不设 ARTEX_PG_DSN 时,DSN 必须拒绝回落到 config.json——
// 那是 2026-10-14 生产库被测试夹具污染的事故路径。本测试自身就跑在
// go test 二进制里,所以护栏必然生效;正常跑法(带 ARTEX_PG_DSN)不受影响。
func TestDSNGuardRefusesConfigFallback(t *testing.T) {
	t.Setenv("ARTEX_PG_DSN", "")
	_, _, err := DSN()
	if err == nil {
		t.Fatal("in a test binary DSN() must refuse the config.json fallback when ARTEX_PG_DSN is unset")
	}
	if !strings.Contains(err.Error(), "ARTEX_PG_DSN") {
		t.Fatalf("error should tell the user to set ARTEX_PG_DSN, got: %v", err)
	}
}
