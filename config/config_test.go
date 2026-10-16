package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresDSNPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","port":6000,"user":"u","password":"p","dbname":"d","sslmode":"require"}}`), 0o644)
	t.Setenv("ZREC_CONFIG", cfgPath)

	// no env DSN → built from config file fields
	t.Setenv("ZREC_PG_DSN", "")
	got, _, err := PostgresDSN()
	want := "postgres://u:p@10.1.2.3:6000/d?sslmode=require"
	if err != nil || got != want {
		t.Fatalf("from file: got %q err %v want %q", got, err, want)
	}

	// env wins over config file
	t.Setenv("ZREC_PG_DSN", "postgres://envwins/x")
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://envwins/x" {
		t.Fatalf("env should win, got %q err %v", got, err)
	}

	// no env, no file → error (no built-in default)
	t.Setenv("ZREC_PG_DSN", "")
	t.Setenv("ZREC_CONFIG", filepath.Join(dir, "nope.json"))
	if got, _, err := PostgresDSN(); err == nil {
		t.Fatalf("missing config should error, got %q", got)
	}

	// full dsn in config file is used verbatim
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644)
	t.Setenv("ZREC_CONFIG", cfgPath)
	if got, _, err := PostgresDSN(); err != nil || got != "postgres://full/dsn" {
		t.Fatalf("file dsn verbatim, got %q err %v", got, err)
	}
}

// TestEnvLegacyFallback 旧版 ARTEX_ 前缀回退(兼容既有部署习惯)。
func TestEnvLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "legacy.json")
	os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://legacy/x"}}`), 0o644)
	t.Setenv("ZREC_CONFIG", "")
	t.Setenv("ARTEX_CONFIG", cfgPath)
	got, _, err := PostgresDSN()
	if err != nil || got != "postgres://legacy/x" {
		t.Fatalf("旧名回退失效: got %q err %v", got, err)
	}
}
