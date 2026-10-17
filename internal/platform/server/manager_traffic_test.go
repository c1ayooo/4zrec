package server

import (
	"testing"

	"github.com/c1ayooo/4zrec/internal/domain/traffic"
)

// TestHostToolsExposeTrafficReadToolsWithoutCapture 钉住：被动捕获关闭时
// http_probe 仍会独立存证，所以 traffic_search/get/blob 读工具必须继续注入；
// 捕获开关只控制 MITM 代理，不再决定读工具是否存在。
func TestHostToolsExposeTrafficReadToolsWithoutCapture(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	m := &Manager{traffic: tr, trafficOn: false}
	names := map[string]bool{}
	for _, tool := range m.HostTools() {
		names[tool.Name()] = true
	}
	for _, want := range []string{"traffic_search", "traffic_get", "traffic_blob"} {
		if !names[want] {
			t.Errorf("capture off must still expose read-only %s", want)
		}
	}
}
