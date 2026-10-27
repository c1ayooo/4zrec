package cred

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Kit holds the injected ports for credential-use verification.
type Kit struct {
	Fetcher core.Fetcher
	// Endpoints optionally overrides vendor STS/IAM endpoints per provider
	// (e.g. a sovereign-cloud host). Empty values fall back to CloudEndpoints.
	Endpoints map[string]string
}

// New builds a credential kit. The host injects a Fetcher so cloud verification
// still respects proxy/timeout/rate/audit policy.
func New(fetcher core.Fetcher) *Kit { return &Kit{Fetcher: fetcher} }

// NewCapability is the registry constructor: it satisfies core.Spec.New.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return New(deps.Fetcher), nil
}

// Manifest exposes the credential-use tool surface. These tools verify that a
// discovered credential works; they do not discover vulnerabilities.
func (k *Kit) Manifest() core.Manifest {
	return core.Manifest{
		Name: "credkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"fetcher"},
		Tools: []core.ToolSpec{
			{
				Name:        "credential_verify_cloud",
				Description: "Verify a cloud AK/SK with the provider's minimal-read STS/IAM call (aliyun/tencent/aws/huawei/volc). Returns validity, account identity and read-only permission surface. Verify-only; no cloud operation is performed.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "provider":{"type":"string","enum":["aliyun","tencent","aws","huawei","volc"]},
    "access_key":{"type":"string"},
    "secret_key":{"type":"string"}
  },
  "required":["provider","access_key","secret_key"]
}`),
				Risk:           core.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"valid":{"type":"boolean"},"provider":{"type":"string"},"account":{"type":"string"},"message":{"type":"string"}}}`),
				ExtractTargets: func(json.RawMessage) ([]core.Target, error) { return nil, nil },
			},
			{
				Name:        "credential_verify_db",
				Description: "Verify a database credential with a live read-only connection: postgres (current_user/version/permission surface) and redis (raw PING/AUTH/INFO; reachable-without-auth means unauthenticated access). mysql/mongo are unsupported and return an explicit error. No write operation is performed.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "type":{"type":"string","enum":["postgres","redis"]},
    "host":{"type":"string"},
    "port":{"type":"integer"},
    "username":{"type":"string"},
    "password":{"type":"string"},
    "database":{"type":"string","description":"postgres optional (default postgres)"}
  },
  "required":["type","host"]
}`),
				Risk:           core.RiskMedium,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"valid":{"type":"boolean"},"engine":{"type":"string"},"version":{"type":"string"},"message":{"type":"string"}}}`),
				ExtractTargets: hostPortTargets,
			},
			{
				Name:        "credential_verify_ssh",
				Description: "Verify an SSH credential with a live read-only connection: authenticate, then id (user/groups) and sudo -n true (passwordless sudo, high risk). Password or PEM private key. No write operation is performed.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "host":{"type":"string"},
    "port":{"type":"integer"},
    "username":{"type":"string"},
    "password":{"type":"string"},
    "private_key":{"type":"string","description":"PEM private key (either this or password)"}
  },
  "required":["host","username"]
}`),
				Risk:           core.RiskMedium,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"valid":{"type":"boolean"},"banner":{"type":"string"},"message":{"type":"string"}}}`),
				ExtractTargets: hostPortTargets,
			},
		},
	}
}

// kitVersion mirrors the Manifest Version; Normalize stamps it into Meta.
const kitVersion = "0.1.0"

// Call is the envelope shell: every return path from dispatch is normalized so
// Status/OK/Meta and a clamped Summary hold on success and failure alike.
func (k *Kit) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := k.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

// dispatch routes one tool invocation.
func (k *Kit) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "credential_verify_cloud":
		return k.verifyCloud(ctx, call.Input)
	case "credential_verify_db":
		return k.verifyDB(ctx, call.Input)
	case "credential_verify_ssh":
		return k.verifySSH(ctx, call.Input)
	default:
		return core.FailResult(fmt.Errorf("unknown tool %s", call.Tool)), nil
	}
}

func (k *Kit) verifyCloud(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in struct {
		Provider  string `json:"provider"`
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	res, err := k.Verify(ctx, in.Provider, in.AccessKey, in.SecretKey)
	if err != nil {
		return core.FailResult(err), nil
	}
	return core.SuccessResult(cloudSummary(in.Provider, in.AccessKey, res), res)
}

// cloudSummary names the provider and the masked AK (never the raw key) and
// reports the verification conclusion. The AK is masked with MaskKey.
func cloudSummary(provider, accessKey string, res VerifyResult) string {
	mask := MaskKey(strings.TrimSpace(accessKey))
	reason := res.Code
	if reason == "" {
		reason = res.Message
	}
	switch res.Status {
	case StatusValid:
		s := fmt.Sprintf("验证 %s AK %s 有效", provider, mask)
		if res.AccountID != "" {
			s += "，账号 " + res.AccountID
		}
		return s
	case StatusRestricted:
		return fmt.Sprintf("验证 %s AK %s 有效但权限受限：%s", provider, mask, reason)
	case StatusInvalid:
		return fmt.Sprintf("%s AK %s 无效：%s", provider, mask, reason)
	default:
		return fmt.Sprintf("无法验证 %s AK %s：%s", provider, mask, reason)
	}
}

func (k *Kit) verifyDB(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in DBProbeInput
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	res, err := VerifyDB(ctx, in)
	if err != nil {
		return core.FailResult(err), nil
	}
	return core.SuccessResult(dbSummary(in, res), res)
}

// dbSummary names the engine, the credential target and the read result.
func dbSummary(in DBProbeInput, res *DBProbeResult) string {
	typ := strings.ToLower(strings.TrimSpace(in.Type))
	port := in.Port
	if port <= 0 {
		port = DefaultDBPort(typ)
	}
	where := credWhere(in.Username, in.Host, port)
	if res.Authed {
		read := res.Version
		if read == "" {
			read = res.Database
		}
		if read != "" {
			return fmt.Sprintf("验证 %s 凭据 %s 有效，可读 %s", typ, where, read)
		}
		return fmt.Sprintf("验证 %s 凭据 %s 有效", typ, where)
	}
	return fmt.Sprintf("验证 %s 凭据 %s 连接失败：%s", typ, where, res.Detail)
}

func (k *Kit) verifySSH(ctx context.Context, input json.RawMessage) (core.Result, error) {
	var in SSHProbeInput
	if err := json.Unmarshal(input, &in); err != nil {
		return core.FailResult(fmt.Errorf("invalid input: %w", err)), nil
	}
	res, err := VerifySSH(ctx, in)
	if err != nil {
		return core.FailResult(err), nil
	}
	return core.SuccessResult(sshSummary(in, res), res)
}

// sshSummary names the login target and the permission-surface result.
func sshSummary(in SSHProbeInput, res *SSHProbeResult) string {
	port := in.Port
	if port <= 0 {
		port = 22
	}
	where := credWhere(in.Username, in.Host, port)
	switch {
	case res.Authed && res.SudoNOPW:
		return fmt.Sprintf("验证 SSH 凭据 %s 有效，具备 sudo 权限", where)
	case res.Authed:
		return fmt.Sprintf("验证 SSH 凭据 %s 有效，无免密 sudo", where)
	case res.Alive:
		return fmt.Sprintf("SSH 凭据 %s 无效：%s", where, res.Detail)
	default:
		return fmt.Sprintf("SSH 凭据 %s 连接失败：%s", where, res.Detail)
	}
}

// credWhere renders "<user>@<host>:<port>", dropping an empty user.
func credWhere(user, host string, port int) string {
	host = strings.TrimSpace(host)
	if strings.TrimSpace(user) == "" {
		return fmt.Sprintf("%s:%d", host, port)
	}
	return fmt.Sprintf("%s@%s:%d", strings.TrimSpace(user), host, port)
}

// hostPortTargets extracts a host:port target from a db/ssh tool input.
func hostPortTargets(input json.RawMessage) ([]core.Target, error) {
	var in struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return nil, err
	}
	host := strings.TrimSpace(in.Host)
	if host == "" {
		return nil, nil
	}
	hostport := host
	if in.Port > 0 {
		hostport = net.JoinHostPort(host, strconv.Itoa(in.Port))
	}
	t, err := core.TargetFromString(0, hostport)
	if err != nil {
		// Fall back to a bare host target when the host isn't host:port shaped.
		return []core.Target{{Kind: core.TargetHost, Host: host}}, nil
	}
	return []core.Target{t}, nil
}
