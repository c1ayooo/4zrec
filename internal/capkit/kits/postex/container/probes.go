package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// endpointResult is one probed path.
type endpointResult struct {
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
	Unauth bool   `json:"unauth"`
	Error  string `json:"error,omitempty"`
	Note   string `json:"note,omitempty"`
}

var (
	kubeletPaths   = []string{"/pods", "/runningpods/", "/run/"}
	apiserverPaths = []string{"/api", "/api/v1/namespaces", "/version"}
	dockerPaths    = []string{"/version", "/containers/json"}
)

// probeTimeout resolves the per-request timeout, defaulting to 10s.
func probeTimeout(ms int) time.Duration {
	if ms <= 0 {
		return 10 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

// probeBaseURL builds the scheme://host:port base for a probe, honoring an
// explicit target URL, bare host[:port], and scheme/port overrides.
func probeBaseURL(in probeInput, defaultScheme string, defaultPort int) (string, error) {
	raw := strings.TrimSpace(core.FirstNonEmpty(in.Target, in.URL))
	if raw == "" && strings.TrimSpace(in.Host) != "" {
		raw = strings.TrimSpace(in.Host)
		if in.Port > 0 {
			raw = net.JoinHostPort(raw, strconv.Itoa(in.Port))
		}
	}
	if raw == "" {
		return "", fmt.Errorf("target 必填（URL 或 host:port）")
	}
	scheme := strings.TrimSpace(in.Scheme)
	if scheme == "" {
		scheme = defaultScheme
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("invalid target: %q", raw)
		}
		s := u.Scheme
		if s == "" {
			s = defaultScheme
		}
		if strings.TrimSpace(in.Scheme) != "" {
			s = strings.TrimSpace(in.Scheme)
		}
		port := u.Port()
		if in.Port > 0 {
			port = strconv.Itoa(in.Port)
		}
		host := u.Hostname()
		if port != "" {
			host = net.JoinHostPort(host, port)
		}
		return s + "://" + host, nil
	}
	host := raw
	port := strconv.Itoa(defaultPort)
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
	}
	if in.Port > 0 {
		port = strconv.Itoa(in.Port)
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

func ensurePath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func targetOf(base string) core.Target {
	t, _ := core.TargetFromURL(0, base)
	return t
}

func fingerprint(kind, base, extra string) string {
	host := base
	if t := targetOf(base); t.Host != "" {
		host = t.Host
	}
	key := kind + "|" + host
	if extra != "" {
		key += "|" + extra
	}
	return key
}

func (c *Capability) httpDoer() (core.HTTPDoer, *core.Error) {
	if c.deps.HTTP == nil {
		return nil, core.Unavailable("HTTPDoer 未注入（宿主需提供 core.Deps.HTTP）")
	}
	return c.deps.HTTP, nil
}

// get issues one GET through the injected gate-aware HTTPDoer.
func (c *Capability) get(ctx context.Context, url string, timeout time.Duration) (*core.Response, error) {
	return c.deps.HTTP.Do(ctx, core.Request{Method: "GET", URL: url, Timeout: timeout})
}

// --- k8s_kubelet_probe ---

func (c *Capability) kubeletProbe(ctx context.Context, call core.Call) (core.Result, error) {
	start := time.Now()
	var in probeInput
	if e := decodeJSON(call.Input, &in); e != nil {
		return core.FailResult(e), nil
	}
	if _, e := c.httpDoer(); e != nil {
		return core.FailResult(e), nil
	}
	base, err := probeBaseURL(in, "https", 10250)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	paths := in.Paths
	if len(paths) == 0 {
		paths = kubeletPaths
	}
	timeout := probeTimeout(in.TimeoutMS)

	var (
		endpoints []endpointResult
		pods      []KubeletPod
		unauth    bool
		responded bool
		lastErr   error
	)
	for _, p := range paths {
		res, err := c.get(ctx, base+ensurePath(p), timeout)
		if err != nil {
			lastErr = err
			endpoints = append(endpoints, endpointResult{Path: p, Error: err.Error()})
			continue
		}
		responded = true
		ep := endpointResult{Path: p, Status: res.Status}
		if res.Status == 200 && len(strings.TrimSpace(string(res.Body))) > 0 {
			ep.Unauth = true
			unauth = true
			if strings.Contains(p, "pods") || strings.Contains(p, "run") {
				if list, perr := parseKubeletPods(res.Body); perr == nil {
					pods = append(pods, list...)
					ep.Note = fmt.Sprintf("解析 %d 个 pod", len(list))
				}
			}
		}
		endpoints = append(endpoints, ep)
	}
	if !responded && lastErr != nil {
		return core.FailResult(core.TargetUnreachable(lastErr.Error())), nil
	}

	summary := "kubelet 10250 需认证或不可读"
	if unauth {
		summary = fmt.Sprintf("kubelet 10250 未授权可读，解析出 %d 个 pod", len(pods))
	}
	res := dataMap(summary, map[string]any{
		"target": base, "unauth": unauth, "pod_count": len(pods),
		"pods": pods, "endpoints": endpoints,
	})
	res.Meta.Target = base
	if unauth {
		res.Status = core.StatusSuccess
		res.Findings = []core.Finding{{
			Target: targetOf(base), Kind: "k8s_kubelet_unauth",
			Fingerprint: fingerprint("k8s_kubelet_unauth", base, ""),
			Confirmed:   true, Source: "containerkit",
			Evidence: []string{fmt.Sprintf("GET %s/pods -> 200（%d pods）", base, len(pods))},
		}}
		res.Next = []core.NextStep{{
			Tool: "k8s_apiserver_probe", Reason: "kubelet 只读接口未授权，进一步尝试匿名访问 API server 读取 Secret 与 SA token",
			Risk: core.RiskMedium, Preconditions: []string{"目标仍在授权范围"},
		}}
	}
	return stamp(res, call.Tool, start), nil
}

// --- k8s_apiserver_probe ---

func (c *Capability) apiserverProbe(ctx context.Context, call core.Call) (core.Result, error) {
	start := time.Now()
	var in probeInput
	if e := decodeJSON(call.Input, &in); e != nil {
		return core.FailResult(e), nil
	}
	if _, e := c.httpDoer(); e != nil {
		return core.FailResult(e), nil
	}
	base, err := probeBaseURL(in, "https", 6443)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	paths := in.Paths
	if len(paths) == 0 {
		paths = apiserverPaths
	}
	timeout := probeTimeout(in.TimeoutMS)

	var (
		endpoints  []endpointResult
		version    string
		versions   []string
		namespaces []string
		unauth     bool
		responded  bool
		lastErr    error
	)
	for _, p := range paths {
		res, err := c.get(ctx, base+ensurePath(p), timeout)
		if err != nil {
			lastErr = err
			endpoints = append(endpoints, endpointResult{Path: p, Error: err.Error()})
			continue
		}
		responded = true
		ep := endpointResult{Path: p, Status: res.Status}
		if res.Status == 200 && len(strings.TrimSpace(string(res.Body))) > 0 {
			ep.Unauth = true
			unauth = true
			switch {
			case strings.HasSuffix(p, "/version"):
				version = parseAPIServerVersion(res.Body)
				ep.Note = version
			case strings.HasSuffix(p, "/api"):
				versions = parseAPIServerVersions(res.Body)
				ep.Note = fmt.Sprintf("%d 个版本", len(versions))
			case strings.Contains(p, "namespaces"):
				namespaces = parseNamespaceNames(res.Body)
				ep.Note = fmt.Sprintf("%d 个 namespace", len(namespaces))
			}
		}
		endpoints = append(endpoints, ep)
	}
	if !responded && lastErr != nil {
		return core.FailResult(core.TargetUnreachable(lastErr.Error())), nil
	}

	summary := "API server 6443 匿名访问不可用"
	if unauth {
		summary = "API server 6443 允许匿名访问"
		if version != "" {
			summary += "（" + version + "）"
		}
	}
	res := dataMap(summary, map[string]any{
		"target": base, "unauth": unauth, "version": version,
		"versions": versions, "namespaces": namespaces, "endpoints": endpoints,
	})
	res.Meta.Target = base
	if unauth {
		res.Findings = []core.Finding{{
			Target: targetOf(base), Kind: "k8s_apiserver_anon",
			Fingerprint: fingerprint("k8s_apiserver_anon", base, ""),
			Confirmed:   true, Source: "containerkit",
			Evidence: []string{fmt.Sprintf("匿名 GET %s/api 返回 200", base)},
		}}
		res.Next = []core.NextStep{{
			Tool: "k8s_etcd_probe", Reason: "匿名可读 API 发现接口，探测 etcd 未授权读以获取集群 Secret",
			Risk: core.RiskMedium, Preconditions: []string{"目标仍在授权范围"},
		}}
	}
	return stamp(res, call.Tool, start), nil
}

func parseAPIServerVersion(body []byte) string {
	var v struct {
		GitVersion string `json:"gitVersion"`
		Major      string `json:"major"`
		Minor      string `json:"minor"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	if v.GitVersion != "" {
		return v.GitVersion
	}
	if v.Major != "" || v.Minor != "" {
		return "v" + v.Major + "." + v.Minor
	}
	return ""
}

func parseAPIServerVersions(body []byte) []string {
	var v struct {
		Versions []string `json:"versions"`
	}
	_ = json.Unmarshal(body, &v)
	return v.Versions
}

func parseNamespaceNames(body []byte) []string {
	var list struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil
	}
	out := make([]string, 0, len(list.Items))
	for _, it := range list.Items {
		if it.Metadata.Name != "" {
			out = append(out, it.Metadata.Name)
		}
	}
	return out
}

// --- k8s_etcd_probe ---

func (c *Capability) etcdProbe(ctx context.Context, call core.Call) (core.Result, error) {
	start := time.Now()
	var in probeInput
	if e := decodeJSON(call.Input, &in); e != nil {
		return core.FailResult(e), nil
	}
	doer, e := c.httpDoer()
	if e != nil {
		return core.FailResult(e), nil
	}
	base, err := probeBaseURL(in, "http", 2379)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	timeout := probeTimeout(in.TimeoutMS)
	keyPrefix := strings.TrimSpace(in.KeyPrefix)
	if keyPrefix == "" {
		keyPrefix = "/registry/secrets"
	}
	body, err := buildEtcdRangeBody(keyPrefix)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}

	// etcd v2.
	var v2 endpointResult
	v2endpoint := base + "/v2/keys"
	v2Unauth := false
	if res, err := c.get(ctx, v2endpoint, timeout); err != nil {
		v2 = endpointResult{Path: "/v2/keys", Error: err.Error()}
	} else {
		v2 = endpointResult{Path: "/v2/keys", Status: res.Status}
		if res.Status == 200 && len(strings.TrimSpace(string(res.Body))) > 0 {
			v2.Unauth = true
			v2Unauth = true
		}
	}

	// etcd v3.
	var v3 endpointResult
	var keys []EtcdKV
	v3endpoint := base + "/v3/kv/range"
	v3Unauth := false
	res3, err := doer.Do(ctx, core.Request{
		Method: "POST", URL: v3endpoint, Body: body,
		Headers: map[string]string{"Content-Type": "application/json"}, Timeout: timeout,
	})
	if err != nil {
		v3 = endpointResult{Path: "/v3/kv/range", Error: err.Error()}
	} else {
		v3 = endpointResult{Path: "/v3/kv/range", Status: res3.Status}
		if res3.Status == 200 {
			if kvs, perr := parseEtcdRange(res3.Body); perr == nil {
				keys = kvs
				v3Unauth = true
				v3.Note = fmt.Sprintf("%d 个 key", len(kvs))
			} else if bytesContains(res3.Body, "header") {
				v3Unauth = true
			}
		}
	}
	if v3Unauth {
		v3.Unauth = true
	}
	unauth := v2Unauth || v3Unauth

	// Redact values before they cross the envelope boundary.
	safeKeys := make([]EtcdKV, 0, len(keys))
	for _, kv := range keys {
		kv.Value = ""
		safeKeys = append(safeKeys, kv)
	}

	summary := "etcd 2379 未发现未授权读"
	if unauth {
		summary = fmt.Sprintf("etcd 2379 未授权可读（%d 个 key）", len(keys))
	}
	res := dataMap(summary, map[string]any{
		"target": base, "unauth": unauth, "key_count": len(keys),
		"keys": safeKeys, "key_prefix": keyPrefix, "v2": v2, "v3": v3,
	})
	res.Meta.Target = base
	if unauth {
		res.Findings = []core.Finding{{
			Target: targetOf(base), Kind: "k8s_etcd_unauth",
			Fingerprint: fingerprint("k8s_etcd_unauth", base, keyPrefix),
			Confirmed:   true, Source: "containerkit",
			Evidence: []string{fmt.Sprintf("etcd %s 未授权读，key_prefix=%s", base, keyPrefix)},
		}}
	}
	return stamp(res, call.Tool, start), nil
}

func bytesContains(body []byte, sub string) bool { return strings.Contains(string(body), sub) }

// --- docker_api_probe ---

type dockerContainer struct {
	ID    string   `json:"id"`
	Names []string `json:"names,omitempty"`
	Image string   `json:"image,omitempty"`
	State string   `json:"state,omitempty"`
}

func (c *Capability) dockerProbe(ctx context.Context, call core.Call) (core.Result, error) {
	start := time.Now()
	var in probeInput
	if e := decodeJSON(call.Input, &in); e != nil {
		return core.FailResult(e), nil
	}
	doer, e := c.httpDoer()
	if e != nil {
		return core.FailResult(e), nil
	}
	base, err := probeBaseURL(in, "http", 2375)
	if err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	timeout := probeTimeout(in.TimeoutMS)

	var (
		endpoints  []endpointResult
		version    DockerVersion
		containers []dockerContainer
		unauth     bool
		responded  bool
		lastErr    error
	)
	for _, p := range dockerPaths {
		res, err := doer.Do(ctx, core.Request{Method: "GET", URL: base + ensurePath(p), Timeout: timeout})
		if err != nil {
			lastErr = err
			endpoints = append(endpoints, endpointResult{Path: p, Error: err.Error()})
			continue
		}
		responded = true
		ep := endpointResult{Path: p, Status: res.Status}
		if res.Status == 200 && len(strings.TrimSpace(string(res.Body))) > 0 {
			ep.Unauth = true
			unauth = true
			if strings.HasSuffix(p, "/version") {
				if v, perr := parseDockerVersion(res.Body); perr == nil {
					version = v
					ep.Note = v.Version
				}
			}
			if strings.Contains(p, "containers") {
				if list, perr := parseDockerContainers(res.Body); perr == nil {
					containers = list
					ep.Note = fmt.Sprintf("%d 个容器", len(list))
				}
			}
		}
		endpoints = append(endpoints, ep)
	}
	if !responded && lastErr != nil {
		return core.FailResult(core.TargetUnreachable(lastErr.Error())), nil
	}

	summary := "Docker API 需要认证或不可达"
	if unauth {
		summary = fmt.Sprintf("Docker API 未授权（%s），可创建 privileged 容器", version.Version)
	}
	res := dataMap(summary, map[string]any{
		"target": base, "unauth": unauth,
		"api_version": version.APIVersion, "version": version.Version, "os": version.OS,
		"container_count": len(containers), "containers": containers, "endpoints": endpoints,
	})
	res.Meta.Target = base
	if unauth {
		res.Findings = []core.Finding{{
			Target: targetOf(base), Kind: "docker_api_unauth",
			Fingerprint: fingerprint("docker_api_unauth", base, ""),
			Confirmed:   true, Source: "containerkit",
			Evidence: []string{fmt.Sprintf("GET %s/version 未授权返回 200（%s）", base, version.Version)},
		}}
		res.Next = []core.NextStep{{
			Tool: "container_escape_plan", Reason: "Docker API 未授权可创建 privileged 容器并挂载宿主根目录，规划接管路径",
			Risk: core.RiskHigh, Preconditions: []string{"目标仍在授权范围", "已获得可写 session 或可直接调用 daemon"},
		}}
	}
	return stamp(res, call.Tool, start), nil
}

func parseDockerContainers(body []byte) ([]dockerContainer, error) {
	var raw []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Image string   `json:"Image"`
		State string   `json:"State"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make([]dockerContainer, 0, len(raw))
	for _, c := range raw {
		out = append(out, dockerContainer{ID: c.ID, Names: c.Names, Image: c.Image, State: c.State})
	}
	return out, nil
}
