package container

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseKubeletPodsPodList(t *testing.T) {
	body := []byte(`{
      "kind":"PodList","apiVersion":"v1",
      "items":[
        {"metadata":{"name":"web-1","namespace":"default","uid":"u1"},
         "spec":{"nodeName":"node-a","containers":[{"name":"web","image":"nginx"},{"name":"sidecar","image":"envoy"}]},
         "status":{"podIP":"10.1.2.3"}},
        {"metadata":{"name":"db-0","namespace":"kube-system"},
         "spec":{"containers":[{"name":"etcd","image":"etcd"}]}}
      ]
    }`)
	pods, err := parseKubeletPods(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 2 {
		t.Fatalf("pods = %d, want 2", len(pods))
	}
	if pods[0].Name != "web-1" || pods[0].Namespace != "default" || pods[0].NodeName != "node-a" {
		t.Fatalf("pod0 = %+v", pods[0])
	}
	if len(pods[0].Containers) != 2 {
		t.Fatalf("pod0 containers = %v", pods[0].Containers)
	}
	if pods[1].Name != "db-0" || pods[1].Namespace != "kube-system" {
		t.Fatalf("pod1 = %+v", pods[1])
	}
}

func TestParseKubeletPodsRunningPods(t *testing.T) {
	body := []byte(`{"kind":"PodList","apiVersion":"v1","items":[
      {"podRef":{"name":"p1","namespace":"ns1","uid":"x"},"id":"cid1","containers":[{"name":"c1"}]}
    ]}`)
	pods, err := parseKubeletPods(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 1 || pods[0].Name != "p1" || pods[0].Namespace != "ns1" {
		t.Fatalf("pods = %+v", pods)
	}
}

func TestParseKubeletPodsBareArrayAndSingle(t *testing.T) {
	arr := []byte(`[{"metadata":{"name":"only","namespace":"k"}}]`)
	pods, err := parseKubeletPods(arr)
	if err != nil || len(pods) != 1 || pods[0].Name != "only" {
		t.Fatalf("array: %v pods=%+v", err, pods)
	}
	single := []byte(`{"metadata":{"name":"solo","namespace":"k"}}`)
	pods, err = parseKubeletPods(single)
	if err != nil || len(pods) != 1 || pods[0].Name != "solo" {
		t.Fatalf("single: %v pods=%+v", err, pods)
	}
}

func TestParseKubeletPodsErrors(t *testing.T) {
	for _, body := range [][]byte{[]byte(""), []byte("not json"), []byte(`{"kind":"X"}`)} {
		if _, err := parseKubeletPods(body); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
}

func TestParseDockerVersion(t *testing.T) {
	body := []byte(`{
      "Platform":{"Name":"Docker Engine - Community"},
      "Version":"20.10.7","ApiVersion":"1.41","MinAPIVersion":"1.12",
      "GitCommit":"f0df350","GoVersion":"go1.16.5","Os":"linux","Arch":"amd64",
      "KernelVersion":"5.4.0-77-generic","BuildTime":"2021-06-01T00:00:00.000000000+00:00"
    }`)
	v, err := parseDockerVersion(body)
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != "20.10.7" || v.APIVersion != "1.41" || v.OS != "linux" || v.Arch != "amd64" {
		t.Fatalf("version = %+v", v)
	}
	if v.MinAPIVersion != "1.12" || v.KernelVersion == "" {
		t.Fatalf("version = %+v", v)
	}
}

func TestParseDockerVersionErrors(t *testing.T) {
	for _, body := range [][]byte{[]byte(""), []byte("<html>404</html>"), []byte(`{"foo":"bar"}`)} {
		if _, err := parseDockerVersion(body); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
}

func TestParseEtcdRange(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("/registry/secrets/default/token"))
	value := base64.StdEncoding.EncodeToString([]byte("secret-token"))
	body := []byte(`{
      "header":{"cluster_id":"14841639068965178418","member_id":"1","revision":"42","raft_term":"2"},
      "kvs":[{"key":"` + key + `","create_revision":"3","mod_revision":"42","version":"5","value":"` + value + `"}],
      "count":"1"
    }`)
	kvs, err := parseEtcdRange(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(kvs) != 1 {
		t.Fatalf("kvs = %d, want 1", len(kvs))
	}
	if kvs[0].Key != "/registry/secrets/default/token" {
		t.Fatalf("key = %q", kvs[0].Key)
	}
	if kvs[0].Value != "secret-token" {
		t.Fatalf("value = %q", kvs[0].Value)
	}
	if kvs[0].ValueBytes != len("secret-token") || kvs[0].CreateRevision != "3" {
		t.Fatalf("kv = %+v", kvs[0])
	}
	// Secrets must not travel as plaintext previews.
	if !strings.Contains(kvs[0].ValuePreview, "redacted") {
		t.Fatalf("value_preview = %q", kvs[0].ValuePreview)
	}
}

func TestParseEtcdRangeEmptyAndErrors(t *testing.T) {
	kvs, err := parseEtcdRange([]byte(`{"header":{"revision":"1"},"count":"0"}`))
	if err != nil || len(kvs) != 0 {
		t.Fatalf("empty kvs: %v %+v", err, kvs)
	}
	for _, body := range [][]byte{[]byte(""), []byte("nope"), []byte(`{"foo":1}`)} {
		if _, err := parseEtcdRange(body); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
}

func TestBuildEtcdRangeBody(t *testing.T) {
	body, err := buildEtcdRangeBody("/registry/secrets")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	key := decodeB64String(parsed["key"].(string))
	if key != "/registry/secrets" {
		t.Fatalf("key = %q", key)
	}
	end := decodeB64String(parsed["range_end"].(string))
	if end != "/registry/secrett" {
		t.Fatalf("range_end = %q (want last byte incremented)", end)
	}
	if _, err := buildEtcdRangeBody("   "); err == nil {
		t.Fatal("empty prefix must error")
	}
}

func TestIncrementPrefix(t *testing.T) {
	cases := []struct {
		in   []byte
		want []byte
	}{
		{[]byte("abc"), []byte("abd")},
		{[]byte{'a', 0xff}, []byte{'b'}},
		{[]byte{0xff, 0xff}, []byte{0}},
		{[]byte{0x00}, []byte{0x01}},
	}
	for _, c := range cases {
		got := incrementPrefix(c.in)
		if string(got) != string(c.want) {
			t.Fatalf("incrementPrefix(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseCapabilities(t *testing.T) {
	privileged := "Name:\tcat\nCapInh:\t0000000000000000\nCapPrm:\t0000003fffffffff\nCapEff:\t0000003fffffffff\nCapBnd:\t0000003fffffffff\n"
	mask, names := parseCapabilities(privileged)
	if !capSet(mask, capSysAdmin) || !capSet(mask, capDACReadSearch) {
		t.Fatalf("privileged caps missing: mask=%x names=%v", mask, names)
	}
	if fmtCapEff(mask) != "0000003fffffffff" {
		t.Fatalf("fmtCapEff = %q", fmtCapEff(mask))
	}
	found := false
	for _, n := range names {
		if n == "cap_sys_admin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cap_sys_admin not listed: %v", names)
	}

	def := "CapEff:\t00000000a80425fb\n"
	mask, _ = parseCapabilities(def)
	if capSet(mask, capSysAdmin) {
		t.Fatal("default docker caps must not include CAP_SYS_ADMIN")
	}
}

func TestParseEscapeChecks(t *testing.T) {
	out := "ok docker_sock\nno privileged\nok cap_sys_admin\nok cap_sys_admin\nbogus line here\n"
	findings := parseEscapeChecks(out)
	if len(findings) != 3 {
		t.Fatalf("findings = %+v", findings)
	}
	byID := map[string]EscapeFinding{}
	for _, f := range findings {
		byID[f.ID] = f
	}
	if !byID["docker_sock"].Hit || byID["privileged"].Hit || !byID["cap_sys_admin"].Hit {
		t.Fatalf("findings = %+v", findings)
	}
	if byID["docker_sock"].Why == "" {
		t.Fatal("finding must carry why")
	}
}
