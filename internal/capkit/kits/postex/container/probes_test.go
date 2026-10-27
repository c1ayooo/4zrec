package container

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// httpDoer adapts net/http to core.HTTPDoer for hermetic probe tests. It is
// deliberately dumb (no scope/limiter) because the probes' only contract is
// "call HTTPDoer.Do"; gate enforcement lives in the host adapter.
type httpDoer struct{}

func (httpDoer) Do(ctx context.Context, req core.Request) (*core.Response, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	client := &http.Client{Timeout: req.Timeout}
	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return &core.Response{
		Status: resp.StatusCode, Headers: resp.Header, Body: body,
		Duration: time.Since(start), FinalURL: resp.Request.URL.String(),
	}, nil
}

func newCap(t *testing.T, deps core.Deps) core.Capability {
	t.Helper()
	c, err := NewCapability(deps)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func doCall(t *testing.T, c core.Capability, tool string, input any) core.Result {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Call(context.Background(), core.Call{Tool: tool, Input: raw})
	if err != nil {
		t.Fatalf("Call returned transport error: %v", err)
	}
	return res
}

func decodeData(t *testing.T, res core.Result) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(res.Data, &m); err != nil {
		t.Fatalf("decode data: %v (%s)", err, res.Data)
	}
	return m
}

func TestKubeletProbeUnauthHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pods":
			_, _ = w.Write([]byte(`{"kind":"PodList","items":[{"metadata":{"name":"web","namespace":"default"},"spec":{"containers":[{"name":"web"}]}}]}`))
		case "/runningpods/":
			_, _ = w.Write([]byte(`{"kind":"PodList","items":[{"podRef":{"name":"run","namespace":"ns"}}]}`))
		case "/run/":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "k8s_kubelet_probe", map[string]any{"target": srv.URL})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q (%s)", res.Status, res.Summary)
	}
	data := decodeData(t, res)
	if data["unauth"] != true {
		t.Fatalf("unauth = %v", data["unauth"])
	}
	if got := data["pod_count"].(float64); got < 2 {
		t.Fatalf("pod_count = %v", got)
	}
	if len(res.Findings) != 1 || !res.Findings[0].Confirmed || res.Findings[0].Kind != "k8s_kubelet_unauth" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(res.Next) == 0 {
		t.Fatal("unauth finding must carry next steps")
	}
	if res.Meta.Tool != "k8s_kubelet_probe" {
		t.Fatalf("meta.tool = %q", res.Meta.Tool)
	}
}

func TestKubeletProbeAuthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"kind":"Status","code":401}`))
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "k8s_kubelet_probe", map[string]any{"target": srv.URL})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status = %q", res.Status)
	}
	data := decodeData(t, res)
	if data["unauth"] != false {
		t.Fatalf("unauth = %v", data["unauth"])
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestKubeletProbeUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := srv.URL
	srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "k8s_kubelet_probe", map[string]any{"target": target})
	if res.Status != core.StatusFailed {
		t.Fatalf("status = %q", res.Status)
	}
	if res.Error == nil || res.Error.Code != core.CodeTargetUnreachable {
		t.Fatalf("error = %+v", res.Error)
	}
}

func TestKubeletProbeMissingHTTPUnavailable(t *testing.T) {
	c := newCap(t, core.Deps{})
	res := doCall(t, c, "k8s_kubelet_probe", map[string]any{"target": "10.0.0.1:10250"})
	if res.Status != core.StatusUnavailable {
		t.Fatalf("status = %q", res.Status)
	}
	if res.Error == nil || res.Error.Code != core.CodeUnavailable {
		t.Fatalf("error = %+v", res.Error)
	}
}

func TestAPIServerProbeAnonymous(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			_, _ = w.Write([]byte(`{"kind":"APIVersions","versions":["v1"]}`))
		case "/version":
			_, _ = w.Write([]byte(`{"major":"1","minor":"27","gitVersion":"v1.27.3"}`))
		case "/api/v1/namespaces":
			_, _ = w.Write([]byte(`{"kind":"NamespaceList","items":[{"metadata":{"name":"default"}},{"metadata":{"name":"kube-system"}}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "k8s_apiserver_probe", map[string]any{"target": srv.URL})
	data := decodeData(t, res)
	if data["unauth"] != true {
		t.Fatalf("unauth = %v", data["unauth"])
	}
	if data["version"] != "v1.27.3" {
		t.Fatalf("version = %v", data["version"])
	}
	ns, _ := data["namespaces"].([]any)
	if len(ns) != 2 {
		t.Fatalf("namespaces = %v", data["namespaces"])
	}
	if len(res.Findings) != 1 || res.Findings[0].Kind != "k8s_apiserver_anon" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestAPIServerProbeForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","code":403}`))
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "k8s_apiserver_probe", map[string]any{"target": srv.URL})
	if decodeData(t, res)["unauth"] != false {
		t.Fatal("403 must not be reported as anonymous access")
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestEtcdProbeV3Unauth(t *testing.T) {
	key := "L3JlZ2lzdHJ5L3NlY3JldHMvZGVmYXVsdC90b2tlbg==" // /registry/secrets/default/token
	value := "dG9rZW4="
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v3/kv/range":
			_, _ = w.Write([]byte(`{"header":{"revision":"7"},"kvs":[{"key":"` + key + `","value":"` + value + `","create_revision":"1","mod_revision":"7","version":"1"}],"count":"1"}`))
		case r.URL.Path == "/v2/keys":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "k8s_etcd_probe", map[string]any{"target": srv.URL})
	data := decodeData(t, res)
	if data["unauth"] != true {
		t.Fatalf("unauth = %v", data["unauth"])
	}
	if data["key_count"].(float64) != 1 {
		t.Fatalf("key_count = %v", data["key_count"])
	}
	keys, _ := data["keys"].([]any)
	first, _ := keys[0].(map[string]any)
	if first["key"] != "/registry/secrets/default/token" {
		t.Fatalf("key = %v", first["key"])
	}
	if _, leaked := first["value"]; leaked {
		t.Fatal("secret value must be stripped from the envelope")
	}
	if len(res.Findings) != 1 || res.Findings[0].Kind != "k8s_etcd_unauth" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestEtcdProbeMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"auth: user name is empty"}`))
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "k8s_etcd_probe", map[string]any{"target": srv.URL})
	if decodeData(t, res)["unauth"] != false {
		t.Fatal("403 must not be reported as unauth etcd")
	}
}

func TestDockerProbeUnauth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"Version":"20.10.7","ApiVersion":"1.41","Os":"linux","Arch":"amd64"}`))
		case "/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"abc","Names":["/web"],"Image":"nginx","State":"running"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "docker_api_probe", map[string]any{"target": srv.URL})
	data := decodeData(t, res)
	if data["unauth"] != true || data["version"] != "20.10.7" {
		t.Fatalf("data = %v", data)
	}
	if data["container_count"].(float64) != 1 {
		t.Fatalf("container_count = %v", data["container_count"])
	}
	if len(res.Findings) != 1 || res.Findings[0].Kind != "docker_api_unauth" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(res.Next) == 0 {
		t.Fatal("docker unauth must suggest next steps")
	}
}

func TestDockerProbeAuthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"page not found"}`))
	}))
	defer srv.Close()

	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "docker_api_probe", map[string]any{"target": srv.URL})
	if decodeData(t, res)["unauth"] != false {
		t.Fatal("401 must not be reported as unauth docker api")
	}
}

func TestProbeBaseURL(t *testing.T) {
	cases := []struct {
		in       probeInput
		scheme   string
		port     int
		expected string
	}{
		{probeInput{Target: "https://10.0.0.1:10250/path"}, "https", 10250, "https://10.0.0.1:10250"},
		{probeInput{Target: "10.0.0.1:10250"}, "https", 10250, "https://10.0.0.1:10250"},
		{probeInput{Target: "10.0.0.1"}, "http", 2379, "http://10.0.0.1:2379"},
		{probeInput{Host: "kube.local", Port: 6443}, "https", 6443, "https://kube.local:6443"},
		{probeInput{Target: "http://1.2.3.4", Port: 2375}, "http", 2375, "http://1.2.3.4:2375"},
	}
	for _, c := range cases {
		got, err := probeBaseURL(c.in, c.scheme, c.port)
		if err != nil {
			t.Fatalf("%+v: %v", c.in, err)
		}
		if got != c.expected {
			t.Fatalf("probeBaseURL(%+v) = %q, want %q", c.in, got, c.expected)
		}
	}
	if _, err := probeBaseURL(probeInput{}, "https", 10250); err == nil {
		t.Fatal("empty target must error")
	}
}

func TestUnknownToolNotFound(t *testing.T) {
	c := newCap(t, core.Deps{HTTP: httpDoer{}})
	res := doCall(t, c, "no_such_tool", map[string]any{})
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("res = %+v", res)
	}
}

func TestManifestContract(t *testing.T) {
	m := Manifest()
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	if m.Name != "containerkit" || m.Version != "0.1.0" || m.APIVersion != "v1" {
		t.Fatalf("manifest header = %+v", m)
	}
	wantReq := map[string]bool{"scope": true, "limiter": true, "audit": true, "http": true, "sessions": true}
	for _, r := range m.Requires {
		delete(wantReq, r)
	}
	if len(wantReq) != 0 {
		t.Fatalf("missing requirements: %v", wantReq)
	}
	if len(m.Tools) != 6 {
		t.Fatalf("tools = %d, want 6", len(m.Tools))
	}
	probes := map[string]bool{
		"k8s_kubelet_probe": true, "k8s_apiserver_probe": true,
		"k8s_etcd_probe": true, "docker_api_probe": true,
	}
	for _, tool := range m.Tools {
		if len(tool.InputSchema) == 0 || len(tool.OutputSchema) == 0 {
			t.Fatalf("%s: empty schema", tool.Name)
		}
		var v any
		if err := json.Unmarshal(tool.InputSchema, &v); err != nil {
			t.Fatalf("%s: invalid input_schema: %v", tool.Name, err)
		}
		if !tool.Risk.Valid() {
			t.Fatalf("%s: invalid risk %q", tool.Name, tool.Risk)
		}
		if probes[tool.Name] {
			if tool.ExtractTargets == nil {
				t.Fatalf("%s: network probe must declare ExtractTargets", tool.Name)
			}
		} else if tool.ExtractTargets != nil {
			if _, err := tool.ExtractTargets(json.RawMessage(`{}`)); err != nil {
				t.Fatalf("%s: no-target tool must return nil targets: %v", tool.Name, err)
			}
		}
	}
}

func TestExtractProbeTarget(t *testing.T) {
	targets, err := extractProbeTarget(json.RawMessage(`{"target":"https://10.0.0.1:10250"}`))
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets = %+v err=%v", targets, err)
	}
	if targets[0].Host != "10.0.0.1" || targets[0].Port != 10250 {
		t.Fatalf("target = %+v", targets[0])
	}
	if _, err := extractProbeTarget(json.RawMessage(`{}`)); err == nil {
		t.Fatal("empty input must error")
	}
}
