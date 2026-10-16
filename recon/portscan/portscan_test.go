package portscan

import (
	"reflect"
	"testing"
)

func TestResolvePortsTop100(t *testing.T) {
	ports := ResolvePorts("top100", "")
	if len(ports) == 0 {
		t.Fatal("top100 不应为空")
	}
	if !contains(ports, 80) || !contains(ports, 443) || !contains(ports, 3389) {
		t.Fatal("top100 应含 80/443/3389")
	}
}

func TestResolvePortsWeb(t *testing.T) {
	ports := ResolvePorts("web", "")
	if !reflect.DeepEqual(ports, WebPorts) {
		t.Fatalf("web 集应与 WebPorts 一致: %v", ports)
	}
}

func TestResolvePortsCustom(t *testing.T) {
	ports := ResolvePorts("", "80,8000-8003,99999,0,abc")
	want := []int{80, 8000, 8001, 8002, 8003}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("custom 解析不符: got %v want %v", ports, want)
	}
}

func TestResolvePortsCustomMergesSet(t *testing.T) {
	ports := ResolvePorts("web", "8443")
	if !contains(ports, 80) || !contains(ports, 8443) {
		t.Fatalf("custom 应并入 set: %v", ports)
	}
}

func TestGuessService(t *testing.T) {
	cases := map[int]string{22: "ssh", 443: "https", 3389: "rdp", 12345: ""}
	for port, want := range cases {
		if got := GuessService(port); got != want {
			t.Fatalf("GuessService(%d) = %q, want %q", port, got, want)
		}
	}
}

func contains(list []int, v int) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
