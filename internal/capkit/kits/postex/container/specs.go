package container

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// probeInput is the shared input of the four network probes. target may be a
// scheme URL (https://10.0.0.1:10250) or a bare host[:port]; host/port are
// accepted as an alternative spelling.
type probeInput struct {
	Target    string   `json:"target"`
	URL       string   `json:"url"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Scheme    string   `json:"scheme"`
	Paths     []string `json:"paths"`
	TimeoutMS int      `json:"timeout_ms"`
	// KeyPrefix is used by k8s_etcd_probe only.
	KeyPrefix string `json:"key_prefix"`
}

// extractProbeTarget pulls the scope-checkable target out of a probe input so
// the runtime can enforce scope before the tool runs. It is shared by all four
// network probes.
func extractProbeTarget(input json.RawMessage) ([]core.Target, error) {
	var in probeInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, err
	}
	raw := core.FirstNonEmpty(in.Target, in.URL)
	if raw == "" && strings.TrimSpace(in.Host) != "" {
		if in.Port > 0 {
			raw = net.JoinHostPort(in.Host, strconv.Itoa(in.Port))
		} else {
			raw = in.Host
		}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("target 必填（URL 或 host:port）")
	}
	t, err := core.TargetFromString(0, raw)
	if err != nil {
		return nil, err
	}
	return []core.Target{t}, nil
}

// noTargets marks tools that act on an existing session or on local data only,
// so they declare no network target for scope enforcement.
func noTargets(json.RawMessage) ([]core.Target, error) { return nil, nil }

const probeTargetSchema = `{"type":"string","description":"目标地址，如 https://10.0.0.1:10250 或 10.0.0.1:10250"}`

func kubeletProbeSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "k8s_kubelet_probe",
		Description: "探测 kubelet 10250 只读接口（/pods、/runningpods/、/run/）是否未授权可读，并把响应解析为 pod/namespace 列表。请求经宿主 HTTPDoer 发送，受 scope/限速/审计约束。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 5, Burst: 3, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":` + probeTargetSchema + `,
    "host":{"type":"string","description":"target 的替代写法"},
    "port":{"type":"integer","description":"默认 10250"},
    "scheme":{"type":"string","enum":["https","http"],"description":"默认 https"},
    "paths":{"type":"array","items":{"type":"string"},"description":"默认 /pods、/runningpods/、/run/"},
    "timeout_ms":{"type":"integer","description":"默认 10000"}
  },
  "required":["target"]
}`),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"},"unauth":{"type":"boolean"},"pod_count":{"type":"integer"},"pods":{"type":"array","items":{"type":"object"}},"endpoints":{"type":"array","items":{"type":"object"}}}}`),
		ExtractTargets: extractProbeTarget,
	}
}

func apiserverProbeSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "k8s_apiserver_probe",
		Description: "探测 API server 6443 的匿名访问（/api、/api/v1/namespaces、/version），报告匿名是否可用以及暴露的版本与 namespace。请求经宿主 HTTPDoer 发送。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 5, Burst: 3, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":` + probeTargetSchema + `,
    "host":{"type":"string"},
    "port":{"type":"integer","description":"默认 6443"},
    "scheme":{"type":"string","enum":["https","http"],"description":"默认 https"},
    "paths":{"type":"array","items":{"type":"string"},"description":"默认 /api、/api/v1/namespaces、/version"},
    "timeout_ms":{"type":"integer","description":"默认 10000"}
  },
  "required":["target"]
}`),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"},"unauth":{"type":"boolean"},"version":{"type":"string"},"versions":{"type":"array","items":{"type":"string"}},"namespaces":{"type":"array","items":{"type":"string"}},"endpoints":{"type":"array","items":{"type":"object"}}}}`),
		ExtractTargets: extractProbeTarget,
	}
}

func etcdProbeSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "k8s_etcd_probe",
		Description: "探测 etcd 2379 的 /v2/keys 与 /v3/kv/range 未授权读。v3 请求体按 key_prefix 构造 base64 前缀扫描（默认 /registry/secrets），用于发现集群 Secret。请求经宿主 HTTPDoer 发送。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 4, Burst: 2, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":` + probeTargetSchema + `,
    "host":{"type":"string"},
    "port":{"type":"integer","description":"默认 2379"},
    "scheme":{"type":"string","enum":["http","https"],"description":"默认 http"},
    "key_prefix":{"type":"string","description":"v3 前缀扫描键，默认 /registry/secrets"},
    "timeout_ms":{"type":"integer","description":"默认 10000"}
  },
  "required":["target"]
}`),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"},"unauth":{"type":"boolean"},"key_count":{"type":"integer"},"keys":{"type":"array","items":{"type":"object"}},"v2":{"type":"object"},"v3":{"type":"object"}}}`),
		ExtractTargets: extractProbeTarget,
	}
}

func dockerProbeSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "docker_api_probe",
		Description: "探测 Docker daemon 2375/2376 的 /version 与 /containers/json 是否未授权。未授权即可创建 privileged 容器并挂载宿主根目录。请求经宿主 HTTPDoer 发送。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 5, Burst: 3, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":` + probeTargetSchema + `,
    "host":{"type":"string"},
    "port":{"type":"integer","description":"默认 2375（TLS 为 2376）"},
    "scheme":{"type":"string","enum":["http","https"],"description":"默认 http"},
    "timeout_ms":{"type":"integer","description":"默认 10000"}
  },
  "required":["target"]
}`),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"target":{"type":"string"},"unauth":{"type":"boolean"},"api_version":{"type":"string"},"version":{"type":"string"},"os":{"type":"string"},"container_count":{"type":"integer"},"containers":{"type":"array","items":{"type":"object"}},"endpoints":{"type":"array","items":{"type":"object"}}}}`),
		ExtractTargets: extractProbeTarget,
	}
}

func escapeCheckSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "container_escape_check",
		Description: "对已建立的 session 运行一组只读、有界的容器逃逸面检查（docker.sock、privileged、capabilities、release_agent、core_pattern、宿主 PID 等），返回结构化逃逸面与 findings。不执行任何逃逸动作。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 4, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string","description":"已有 session 的 ID"},
    "timeout_ms":{"type":"integer","description":"单条命令超时，默认 10000"},
    "max_output":{"type":"integer","description":"单条命令输出上限字节，默认 4096"}
  },
  "required":["session_id"]
}`),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"session_id":{"type":"string"},"host":{"type":"string"},"docker_sock":{"type":"boolean"},"docker_sock_mounted":{"type":"boolean"},"privileged":{"type":"boolean"},"cap_sys_admin":{"type":"boolean"},"cap_dac_read_search":{"type":"boolean"},"release_agent_writable":{"type":"boolean"},"core_pattern_writable":{"type":"boolean"},"host_pid":{"type":"boolean"},"host_devices":{"type":"boolean"},"proc_sys_writable":{"type":"boolean"},"capabilities":{"type":"array","items":{"type":"string"}},"checks":{"type":"array","items":{"type":"object"}}}}`),
		ExtractTargets: noTargets,
	}
}

func escapePlanSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "container_escape_plan",
		Description: "根据 container_escape_check 的结果（surface 对象或 session_id）返回按可利用性排序的候选逃逸技术，每条为一个 NextStep（tool/reason/preconditions/risk）。纯决策支持，不执行任何逃逸动作。",
		Risk:        core.RiskLow,
		RateLimit:   core.RateLimitSpec{PerSecond: 10, Burst: 5, Concurrency: 4},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string","description":"可选：无 surface 时先用只读检查推导"},
    "surface":{"type":"object","description":"container_escape_check 返回的逃逸面对象"},
    "timeout_ms":{"type":"integer"}
  }
}`),
		OutputSchema:   json.RawMessage(`{"type":"object","properties":{"count":{"type":"integer"},"techniques":{"type":"array","items":{"type":"object"}},"surface":{"type":"object"}}}`),
		ExtractTargets: noTargets,
	}
}
