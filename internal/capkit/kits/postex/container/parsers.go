package container

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// This file holds the pure, side-effect-free parsers used by the probe and
// escape tools. They are kept free of I/O so they can be unit tested with
// realistic payloads and reused by hosts that already have raw responses.

// KubeletPod is one pod as reported by the kubelet read-only API
// (GET /pods, /runningpods/, /run/). Both the PodList shape ("metadata") and
// the runningpods shape ("podRef") are normalized into this struct.
type KubeletPod struct {
	Namespace  string   `json:"namespace,omitempty"`
	Name       string   `json:"name,omitempty"`
	UID        string   `json:"uid,omitempty"`
	NodeName   string   `json:"node_name,omitempty"`
	PodIP      string   `json:"pod_ip,omitempty"`
	Containers []string `json:"containers,omitempty"`
}

// kubeletItem covers both payload variants the kubelet emits.
type kubeletItem struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	PodRef struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"podRef"`
	Spec struct {
		NodeName   string `json:"nodeName"`
		Containers []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"spec"`
	Status struct {
		PodIP string `json:"podIP"`
	} `json:"status"`
}

func (it kubeletItem) toPod() KubeletPod {
	p := KubeletPod{
		Namespace: it.Metadata.Namespace,
		Name:      it.Metadata.Name,
		UID:       it.Metadata.UID,
		NodeName:  it.Spec.NodeName,
		PodIP:     it.Status.PodIP,
	}
	if p.Name == "" { // runningpods variant
		p.Name = it.PodRef.Name
		p.Namespace = it.PodRef.Namespace
		p.UID = it.PodRef.UID
	}
	for _, c := range it.Spec.Containers {
		if c.Name != "" {
			p.Containers = append(p.Containers, c.Name)
		}
	}
	return p
}

// parseKubeletPods parses a kubelet /pods or /runningpods/ JSON payload into a
// normalized pod list. It accepts a PodList ({"items":[...]}), the runningpods
// variant (also {"items":[...]} with "podRef"), a bare JSON array, and a single
// pod object. An empty/undecodable body is an error so callers can tell
// "unauthenticated but empty" from "not JSON".
func parseKubeletPods(body []byte) ([]KubeletPod, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("empty kubelet response")
	}
	if trimmed[0] == '[' {
		var items []kubeletItem
		if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
			return nil, fmt.Errorf("kubelet array: %w", err)
		}
		return podsFromItems(items), nil
	}
	var list struct {
		Items []kubeletItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
		return nil, fmt.Errorf("kubelet json: %w", err)
	}
	if list.Items != nil {
		return podsFromItems(list.Items), nil
	}
	var single kubeletItem
	if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
		return nil, fmt.Errorf("kubelet json: %w", err)
	}
	if single.Metadata.Name == "" && single.PodRef.Name == "" {
		return nil, fmt.Errorf("unrecognized kubelet payload")
	}
	return []KubeletPod{single.toPod()}, nil
}

func podsFromItems(items []kubeletItem) []KubeletPod {
	out := make([]KubeletPod, 0, len(items))
	for _, it := range items {
		out = append(out, it.toPod())
	}
	return out
}

// DockerVersion is the subset of GET /version that matters for triage.
type DockerVersion struct {
	Version       string `json:"version,omitempty"`
	APIVersion    string `json:"api_version,omitempty"`
	MinAPIVersion string `json:"min_api_version,omitempty"`
	OS            string `json:"os,omitempty"`
	Arch          string `json:"arch,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
	GitCommit     string `json:"git_commit,omitempty"`
}

// parseDockerVersion parses the Docker Engine /version response.
func parseDockerVersion(body []byte) (DockerVersion, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return DockerVersion{}, fmt.Errorf("empty docker response")
	}
	var raw struct {
		Version       string `json:"Version"`
		APIVersion    string `json:"ApiVersion"`
		MinAPIVersion string `json:"MinAPIVersion"`
		OS            string `json:"Os"`
		Arch          string `json:"Arch"`
		KernelVersion string `json:"KernelVersion"`
		GitCommit     string `json:"GitCommit"`
	}
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return DockerVersion{}, fmt.Errorf("docker version json: %w", err)
	}
	if raw.Version == "" && raw.APIVersion == "" {
		return DockerVersion{}, fmt.Errorf("unrecognized docker version payload")
	}
	return DockerVersion{
		Version: raw.Version, APIVersion: raw.APIVersion, MinAPIVersion: raw.MinAPIVersion,
		OS: raw.OS, Arch: raw.Arch, KernelVersion: raw.KernelVersion, GitCommit: raw.GitCommit,
	}, nil
}

// EtcdKV is one key/value pair returned by parseEtcdRange (etcd v3 JSON
// gateway response).
type EtcdKV struct {
	Key            string `json:"key"`
	Value          string `json:"value,omitempty"`
	ValueBytes     int    `json:"value_bytes,omitempty"`
	ValuePreview   string `json:"value_preview,omitempty"`
	CreateRevision string `json:"create_revision,omitempty"`
	ModRevision    string `json:"mod_revision,omitempty"`
	Version        string `json:"version,omitempty"`
}

// parseEtcdRange parses an etcd v3 /v3/kv/range JSON response, base64-decoding
// keys and values. A valid response with zero kvs returns an empty slice and no
// error; malformed JSON is an error.
func parseEtcdRange(body []byte) ([]EtcdKV, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, fmt.Errorf("empty etcd response")
	}
	var resp struct {
		Header json.RawMessage `json:"header"`
		Kvs    []struct {
			Key            string `json:"key"`
			Value          string `json:"value"`
			CreateRevision string `json:"create_revision"`
			ModRevision    string `json:"mod_revision"`
			Version        string `json:"version"`
		} `json:"kvs"`
	}
	if err := json.Unmarshal([]byte(trimmed), &resp); err != nil {
		return nil, fmt.Errorf("etcd range json: %w", err)
	}
	if resp.Header == nil && resp.Kvs == nil {
		return nil, fmt.Errorf("unrecognized etcd payload")
	}
	out := make([]EtcdKV, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		key := decodeB64String(kv.Key)
		value := decodeB64String(kv.Value)
		out = append(out, EtcdKV{
			Key:            key,
			ValueBytes:     len(value),
			ValuePreview:   previewValue(key, value),
			CreateRevision: kv.CreateRevision,
			ModRevision:    kv.ModRevision,
			Version:        kv.Version,
			Value:          value,
		})
	}
	return out, nil
}

// buildEtcdRangeBody builds the JSON body for etcd v3 POST /v3/kv/range that
// scans every key sharing a prefix (e.g. "/registry/secrets"). range_end is the
// prefix with its last byte incremented, the etcd convention for a prefix scan.
func buildEtcdRangeBody(keyPrefix string) ([]byte, error) {
	prefix := strings.TrimSpace(keyPrefix)
	if prefix == "" {
		return nil, fmt.Errorf("key_prefix is required")
	}
	key := base64.StdEncoding.EncodeToString([]byte(prefix))
	rangeEnd := base64.StdEncoding.EncodeToString(incrementPrefix([]byte(prefix)))
	body, err := json.Marshal(map[string]any{
		"key":       key,
		"range_end": rangeEnd,
		"limit":     100,
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

// incrementPrefix returns the smallest key strictly greater than every key with
// the given prefix, by incrementing the final byte and dropping trailing 0xFF
// bytes. An all-0xFF prefix collapses to "\x00" (scan to the end of the store).
func incrementPrefix(p []byte) []byte {
	b := append([]byte(nil), p...)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return b[:i+1]
		}
	}
	return []byte{0}
}

func decodeB64String(s string) string {
	if s == "" {
		return ""
	}
	// Prefer padded standard base64; only fall back to the raw alphabet when the
	// input is genuinely unpadded. etcd always emits padded base64, so this keeps
	// stdin-free values from being silently mangled.
	enc := base64.StdEncoding
	if !strings.HasSuffix(s, "=") && len(s)%4 != 0 {
		enc = base64.RawStdEncoding
	}
	decoded, err := enc.DecodeString(s)
	if err != nil {
		if raw, err2 := base64.RawStdEncoding.DecodeString(s); err2 == nil {
			return string(raw)
		}
		return s
	}
	return string(decoded)
}

// previewValue trims a decoded secret value to a safe bounded preview. Values
// whose etcd key looks like a Kubernetes Secret are always redacted to a
// length-only marker so the envelope never leaks plaintext credentials.
func previewValue(key, value string) string {
	if strings.Contains(key, "/secrets/") || strings.Contains(key, "/registry/secrets") {
		return fmt.Sprintf("<secret %d bytes redacted>", len(value))
	}
	const max = 120
	if len(value) > max {
		return value[:max] + "…"
	}
	return value
}

// Capability bits used by the escape triage (Linux capability set).
const (
	capDACReadSearch = 2
	capDACOverride   = 4
	capSetUID        = 7
	capSetGID        = 6
	capNetAdmin      = 12
	capNetRaw        = 13
	capSysModule     = 16
	capSysRawIO      = 17
	capSysPTrace     = 19
	capSysAdmin      = 21
	capSysBoot       = 22
	capMknod         = 27
)

var namedCaps = []struct {
	name string
	bit  uint
}{
	{"cap_dac_read_search", capDACReadSearch},
	{"cap_dac_override", capDACOverride},
	{"cap_sys_admin", capSysAdmin},
	{"cap_sys_ptrace", capSysPTrace},
	{"cap_sys_module", capSysModule},
	{"cap_sys_rawio", capSysRawIO},
	{"cap_net_admin", capNetAdmin},
	{"cap_net_raw", capNetRaw},
	{"cap_setuid", capSetUID},
	{"cap_mknod", capMknod},
}

// parseCapabilities parses the CapEff/CapPrm/CapBnd lines of /proc/self/status.
// It returns the CapEff bitmask and the sorted names of the interesting
// capabilities that are effective.
func parseCapabilities(out string) (uint64, []string) {
	var eff uint64
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		if v, err := strconv.ParseUint(hex, 16, 64); err == nil {
			eff = v
		}
	}
	var names []string
	for _, c := range namedCaps {
		if eff&(uint64(1)<<c.bit) != 0 {
			names = append(names, c.name)
		}
	}
	sort.Strings(names)
	return eff, names
}

func capSet(mask uint64, bit uint) bool { return mask&(uint64(1)<<bit) != 0 }

// fmtCapEff renders a mask the way /proc/self/status would (16 hex digits).
func fmtCapEff(mask uint64) string { return fmt.Sprintf("%016x", mask) }
