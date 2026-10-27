package listener

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestListenerExecAndFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	m := NewManager()
	addr, err := m.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	go func() {
		conn, derr := net.Dial("tcp", addr)
		if derr != nil {
			return
		}
		defer conn.Close()
		cmd := exec.Command("/bin/sh")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
		_ = cmd.Run()
	}()

	var sess SessionInfo
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if list := m.Sessions(); len(list) > 0 {
			sess = list[0]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sess.ID == "" {
		t.Fatal("no reverse session accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := m.Exec(ctx, sess.ID, "echo hello")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "hello") {
		t.Fatalf("exec output = %q", out)
	}
	path := filepath.Join(t.TempDir(), "upload.txt")
	if _, err := m.Upload(ctx, sess.ID, path, []byte("hello file")); err != nil {
		t.Fatal(err)
	}
	data, err := m.Download(ctx, sess.ID, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello file" {
		t.Fatalf("download = %q", data)
	}
	_, _ = m.Exec(ctx, sess.ID, "rm -f "+quotePath(path))
}
