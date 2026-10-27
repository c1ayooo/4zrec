// Package internalnetkit performs internal-network reconnaissance from an
// established foothold (docs 究极渗透能力包实现方案 §4.10, phase P2).
//
// Everything here runs THROUGH a core.Session: host surveys, live-host
// discovery, port scanning, domain information gathering and SMB share
// enumeration are all executed on the target side with `Exec`, never from the
// machine running the kit. Sessions are resolved from core.Deps.Sessions, so
// a WebShell, SSH, WinRM or CLI foothold is used identically.
//
// Output parsing lives in parse.go as pure functions (cheap to test, fail
// closed: an unparseable command yields an empty result rather than a guess).
package internalnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// Bounds. Every tool caps how much work it will do on the target so an agent
// cannot accidentally fingerprint an entire /8 or SYN-flood a subnet.
const (
	defaultTimeout    = 20 * time.Second
	maxTimeout        = 5 * time.Minute
	defaultCmdTimeout = 8 * time.Second

	discoveryDefaultMaxHosts = 64
	discoveryHardMaxHosts    = 1024

	scanDefaultMaxHosts = 16
	scanHardMaxHosts    = 256
	scanDefaultMaxPorts = 64
	scanHardMaxPorts    = 1024
	scanConcurrency     = 2 // per-host concurrency ceiling

	pingSweepChunk = 128

	kitVersion = "0.1.0"
)

// Capability exposes the internal-network reconnaissance tools.
type Capability struct {
	deps core.Deps
}

// NewCapability builds the capability.
func NewCapability(deps core.Deps) (core.Capability, error) {
	return &Capability{deps: deps}, nil
}

// Manifest declares the internalnetkit tools.
func Manifest() core.Manifest {
	return core.Manifest{
		Name: "internalnetkit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "sessions"},
		Tools: []core.ToolSpec{
			localInfoSpec(),
			hostDiscoverySpec(),
			portScanSpec(),
			domainInfoSpec(),
			smbSharesSpec(),
		},
	}
}

// Manifest implements core.Capability.
func (c *Capability) Manifest() core.Manifest { return Manifest() }

// Call dispatches one tool invocation and normalizes the envelope on every
// return path (Status/OK/Meta.Tool/Meta.Version/Summary clamp).
func (c *Capability) Call(ctx context.Context, call core.Call) (core.Result, error) {
	res, err := c.dispatch(ctx, call)
	return res.Normalize(call.Tool, kitVersion), err
}

// dispatch routes the call to the tool implementation.
func (c *Capability) dispatch(ctx context.Context, call core.Call) (core.Result, error) {
	switch call.Tool {
	case "inet_local_info":
		return c.localInfo(ctx, call)
	case "inet_host_discovery":
		return c.hostDiscovery(ctx, call)
	case "inet_portscan":
		return c.portScan(ctx, call)
	case "inet_domain_info":
		return c.domainInfo(ctx, call)
	case "inet_smb_shares":
		return c.smbShares(ctx, call)
	default:
		return core.FailResult(core.NotFound("unknown tool: " + call.Tool)), nil
	}
}

// ---- session + command helpers ----

func (c *Capability) session(id string) (core.Session, *core.Error) {
	if c.deps.Sessions == nil {
		return nil, core.ToolMissing("SessionManager 未注入（宿主需提供 core.Deps.Sessions）")
	}
	if strings.TrimSpace(id) == "" {
		return nil, core.InvalidInput("session_id 必填")
	}
	s, ok := c.deps.Sessions.Get(id)
	if !ok {
		return nil, core.NotFound("会话不存在: " + id)
	}
	return s, nil
}

// run executes one command through the foothold. A transport error is
// reported as !ok; the caller decides whether that is fatal or partial.
func (c *Capability) run(ctx context.Context, s core.Session, cmd string, timeout time.Duration) (core.Output, bool) {
	out, err := s.Exec(ctx, cmd, core.ExecOpts{Timeout: timeout, MaxOutput: 256 << 10})
	if err != nil {
		return core.Output{Command: cmd}, false
	}
	return out, true
}

func clampMax(v, def, hard int) int {
	if v <= 0 {
		return def
	}
	if v > hard {
		return hard
	}
	return v
}

// detectOS resolves the session OS, probing with `uname -s` when unset.
func (c *Capability) detectOS(ctx context.Context, s core.Session, to time.Duration) string {
	if os := strings.ToLower(strings.TrimSpace(s.Info().OS)); os != "" {
		if strings.Contains(os, "win") {
			return "windows"
		}
		return "linux"
	}
	if out, ok := c.run(ctx, s, "uname -s", to); ok && strings.TrimSpace(out.Stdout) != "" {
		return "linux"
	}
	return "windows"
}

func osName(s core.Session) string { return strings.ToLower(strings.TrimSpace(s.Info().OS)) }

// ---- tool specs ----

func localInfoSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "inet_local_info",
		Description: "在已建立会话的主机上执行有界只读信息收集（主机名、网络接口/路由、OS、用户、登录、ARP、监听端口；Windows 另含 systeminfo/管理员组/进程）。全部命令经会话执行，不触碰本机网络。",
		Risk:        core.RiskLow,
		RateLimit:   core.RateLimitSpec{PerSecond: 2, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "timeout_ms":{"type":"integer","description":"整体命令超时上限，默认 20000"}
  },
  "required":["session_id"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "os":{"type":"string"},"hostname":{"type":"string"},"user":{"type":"string"},
    "kernel":{"type":"string"},"os_release":{"type":"string"},
    "interfaces":{"type":"array","items":{"type":"object"}},
    "routes":{"type":"array","items":{"type":"object"}},
    "users":{"type":"array","items":{"type":"string"}},
    "admins":{"type":"array","items":{"type":"string"}},
    "logins":{"type":"array","items":{"type":"string"}},
    "arp":{"type":"array","items":{"type":"object"}},
    "listeners":{"type":"array","items":{"type":"object"}},
    "processes":{"type":"array","items":{"type":"object"}},
    "errors":{"type":"array","items":{"type":"string"}}
  }
}`),
	}
}

func hostDiscoverySpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "inet_host_discovery",
		Description: "从会话出发对给定 CIDR/网段做存活主机发现（ping 扫描 / arp -a / /dev/tcp 探测），全部经会话 shell 执行。有界：主机数封顶、命令有超时。返回存活主机与证据。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "cidr":{"type":"string","description":"目标网段，如 10.0.0.0/24"},
    "method":{"type":"string","enum":["ping","arp","tcp"],"description":"默认 ping"},
    "max_hosts":{"type":"integer","description":"探测主机数上限，默认 64，硬上限 1024"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id","cidr"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "cidr":{"type":"string"},"method":{"type":"string"},
    "probed":{"type":"integer"},"truncated":{"type":"boolean"},
    "hosts":{"type":"array","items":{"type":"object","properties":{"host":{"type":"string"},"method":{"type":"string"},"mac":{"type":"string"}}}}
  }
}`),
		ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
			var in struct {
				CIDR string `json:"cidr"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return nil, err
			}
			if strings.TrimSpace(in.CIDR) == "" {
				return nil, fmt.Errorf("cidr 必填")
			}
			return core.TargetsFromStrings(0, []string{in.CIDR})
		},
	}
}

func portScanSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "inet_portscan",
		Description: "从会话出发对给定主机/网段做 TCP 端口扫描（bash /dev/tcp 或 nc），返回开放端口与服务名。有界：主机/端口数封顶，单主机并发 <=2。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: scanConcurrency},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "hosts":{"type":"array","items":{"type":"string"},"description":"目标主机列表"},
    "cidr":{"type":"string","description":"可选，与 hosts 合并"},
    "ports":{"type":"string","description":"端口规格，如 \"22,80,443\" 或 \"1-1024\""},
    "tool":{"type":"string","enum":["tcp","nc"],"description":"探测方式，默认 tcp(/dev/tcp)"},
    "max_hosts":{"type":"integer","description":"默认 16，硬上限 256"},
    "max_ports":{"type":"integer","description":"默认 64，硬上限 1024"},
    "per_port_ms":{"type":"integer","description":"单端口超时，默认 1000"},
    "timeout_ms":{"type":"integer"},
    "cursor":{"type":"string","description":"分页游标，用上一次返回的 page.cursor"},
    "page_size":{"type":"integer","description":"单页条数，默认 100"}
  },
  "required":["session_id","ports"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "probed_hosts":{"type":"integer"},"probed_ports":{"type":"integer"},
    "truncated":{"type":"boolean"},
    "open_count":{"type":"integer","description":"本次返回的开放端口条数"},
    "total_open":{"type":"integer","description":"去重后的开放端口总数，分页时用 page.cursor 续取"},
    "open":{"type":"array","items":{"type":"object","properties":{"host":{"type":"string"},"port":{"type":"integer"},"service":{"type":"string"}}}}
  }
}`),
		ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
			var in struct {
				Hosts []string `json:"hosts"`
				CIDR  string   `json:"cidr"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return nil, err
			}
			raws := append([]string{}, in.Hosts...)
			if strings.TrimSpace(in.CIDR) != "" {
				raws = append(raws, in.CIDR)
			}
			if len(raws) == 0 {
				return nil, fmt.Errorf("hosts 或 cidr 至少一个必填")
			}
			return core.TargetsFromStrings(0, raws)
		},
	}
}

func domainInfoSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "inet_domain_info",
		Description: "从会话出发做域信息收集（net user|group /domain、nltest /dclist|/domain_trusts、类 Unix 的 realm/net ads/ldapsearch），解析域、用户、组、信任关系与域控。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "domain":{"type":"string","description":"可选，域 FQDN（用于 nltest /dclist）"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "domain":{"type":"string"},
    "users":{"type":"array","items":{"type":"string"}},
    "groups":{"type":"array","items":{"type":"string"}},
    "trusts":{"type":"array","items":{"type":"string"}},
    "dcs":{"type":"array","items":{"type":"string"}}
  }
}`),
	}
}

func smbSharesSpec() core.ToolSpec {
	return core.ToolSpec{
		Name:        "inet_smb_shares",
		Description: "从会话出发枚举 SMB 共享（Windows net view/net share，类 Unix smbclient -L），返回共享名、类型与访问提示。",
		Risk:        core.RiskMedium,
		RateLimit:   core.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "host":{"type":"string","description":"可选，目标主机/IP；缺省枚举本机共享"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":{"type":"string"},"count":{"type":"integer"},
    "shares":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"type":{"type":"string"},"comment":{"type":"string"},"access":{"type":"string"}}}}
  }
}`),
		ExtractTargets: func(input json.RawMessage) ([]core.Target, error) {
			var in struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return nil, err
			}
			if strings.TrimSpace(in.Host) == "" {
				return nil, nil // local-share enumeration has no remote target
			}
			return core.TargetsFromStrings(0, []string{in.Host})
		},
	}
}

// ---- inet_local_info ----

// LocalInfo is the structured host survey payload.
type LocalInfo struct {
	OS         string         `json:"os,omitempty"`
	Hostname   string         `json:"hostname,omitempty"`
	User       string         `json:"user,omitempty"`
	Kernel     string         `json:"kernel,omitempty"`
	OSRelease  string         `json:"os_release,omitempty"`
	Interfaces []NetInterface `json:"interfaces,omitempty"`
	Routes     []Route        `json:"routes,omitempty"`
	Users      []string       `json:"users,omitempty"`
	Admins     []string       `json:"admins,omitempty"`
	Logins     []string       `json:"logins,omitempty"`
	ARP        []ARPEntry     `json:"arp,omitempty"`
	Listeners  []Listener     `json:"listeners,omitempty"`
	Processes  []Process      `json:"processes,omitempty"`
	Errors     []string       `json:"errors,omitempty"`
}

func (c *Capability) localInfo(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		SessionID string `json:"session_id"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	to := core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	cmdTo := firstDur(to/3, defaultCmdTimeout)
	os := c.detectOS(ctx, s, cmdTo)

	out := LocalInfo{OS: os}
	var outs []core.Output
	collect := func(cmd string) string {
		o, ok := c.run(ctx, s, cmd, cmdTo)
		outs = append(outs, o)
		if !ok {
			out.Errors = append(out.Errors, "命令失败: "+cmd)
			return ""
		}
		return o.Stdout
	}

	out.Hostname = firstLine(collect("hostname"))
	out.User = firstLine(collect("whoami"))

	if os == "windows" {
		out.OSRelease = parseSysteminfo(collect("systeminfo"))
		out.Interfaces = adaptersToInterfaces(parseIpconfig(collect("ipconfig /all")))
		out.Routes = parseRoutePrint(collect("route print"))
		out.Users = parseUserList(collect("net user"))
		out.Admins = parseUserList(collect("net localgroup administrators"))
		out.ARP = parseARP(collect("arp -a"))
		out.Listeners = parseNetstat(collect("netstat -ano"))
		out.Processes = parseTasklist(collect("tasklist"))
	} else {
		out.Kernel = firstLine(collect("uname -a"))
		out.OSRelease = parseOSRelease(collect("cat /etc/os-release 2>/dev/null"))
		out.Interfaces = parseIPAddr(collect("ip addr"))
		out.Routes = parseRoutes(collect("ip route"))
		out.Users = parseUserList(collect("cat /etc/passwd"))
		out.Logins = parseLogins(collect("who") + "\n" + collect("last -n 20 2>/dev/null"))
		out.ARP = parseARP(collect("arp -a"))
		out.Listeners = parseSsListeners(collect("ss -tunlp"))
	}

	res, err := core.SuccessResult(localSummary(&out), out)
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res.Evidence = core.EvidenceRefs(outs...)
	applyLocalStatus(&res, out.Errors)
	res.Next = localNextSteps(in.SessionID, out.Interfaces)
	return res, nil
}

func localSummary(li *LocalInfo) string {
	return fmt.Sprintf("读取 %s 的本地信息：主机名 %s，网卡 %d 张，路由 %d 条，监听 %d 个",
		sessionLabel(li.User, li.Hostname), orDash(li.Hostname),
		len(li.Interfaces), len(li.Routes), len(li.Listeners))
}

// sessionLabel names a foothold as user@host, falling back to whichever half is
// known. It never invents a host.
func sessionLabel(user, host string) string {
	user, host = strings.TrimSpace(user), strings.TrimSpace(host)
	switch {
	case user != "" && host != "":
		return user + "@" + host
	case host != "":
		return host
	case user != "":
		return user
	default:
		return "-"
	}
}

func applyLocalStatus(res *core.Result, errs []string) {
	switch {
	case len(errs) == 0:
		res.Status, res.OK = core.StatusSuccess, true
	case len(errs) >= 4:
		// Nothing useful was collected: fail rather than return an empty shell.
		res.Status, res.OK = core.StatusFailed, false
		res.Error = core.Unavailable("主机信息收集基本失败")
	default:
		res.Status, res.OK = core.StatusPartial, true
	}
}

func localNextSteps(sessionID string, ifaces []NetInterface) []core.NextStep {
	var next []core.NextStep
	for _, cidr := range localCIDRs(ifaces) {
		params, _ := json.Marshal(map[string]any{"session_id": sessionID, "cidr": cidr})
		next = append(next, core.NextStep{
			Tool: "inet_host_discovery", Reason: "对内网网段 " + cidr + " 做存活探测",
			Risk: core.RiskMedium, Params: params,
		})
		if len(next) >= 4 {
			break
		}
	}
	return next
}

func localCIDRs(ifaces []NetInterface) []string {
	var out []string
	seen := map[string]bool{}
	for _, i := range ifaces {
		if strings.HasPrefix(i.Name, "lo") {
			continue
		}
		for _, cidr := range i.IPv4 {
			if strings.HasPrefix(cidr, "127.") {
				continue
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			s := ipnet.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func adaptersToInterfaces(cfg Ipconfig) []NetInterface {
	var out []NetInterface
	for _, a := range cfg.Adapters {
		out = append(out, NetInterface{Name: a.Name, MAC: a.MAC, IPv4: a.IPv4, Mask: a.Mask})
	}
	return out
}

// ---- inet_host_discovery ----

// DiscoveredHost is one live host found through the foothold.
type DiscoveredHost struct {
	Host   string `json:"host"`
	Method string `json:"method,omitempty"`
	MAC    string `json:"mac,omitempty"`
}

// HostDiscovery is the tool payload.
type HostDiscovery struct {
	CIDR      string           `json:"cidr"`
	Method    string           `json:"method"`
	Probed    int              `json:"probed"`
	Truncated bool             `json:"truncated"`
	Hosts     []DiscoveredHost `json:"hosts"`
}

func (c *Capability) hostDiscovery(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		SessionID string `json:"session_id"`
		CIDR      string `json:"cidr"`
		Method    string `json:"method"`
		MaxHosts  int    `json:"max_hosts"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(in.CIDR))
	if err != nil {
		return core.FailResult(core.InvalidInput("cidr 非法: " + in.CIDR)), nil
	}
	if ipnet.IP.To4() == nil {
		return core.FailResult(core.InvalidInput("仅支持 IPv4 网段: " + in.CIDR)), nil
	}
	method := strings.ToLower(strings.TrimSpace(in.Method))
	if method == "" {
		method = "ping"
	}
	if method != "ping" && method != "arp" && method != "tcp" {
		return core.FailResult(core.InvalidInput("method 仅支持 ping|arp|tcp")), nil
	}
	to := core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	cmdTo := firstDur(to, defaultTimeout)
	maxHosts := clampMax(in.MaxHosts, discoveryDefaultMaxHosts, discoveryHardMaxHosts)

	hosts, truncated := enumerateCIDR(ipnet, maxHosts)
	os := c.detectOS(ctx, s, cmdTo)

	alive := map[string]bool{}
	var outs []core.Output

	probe := func(cmd string) string {
		o, ok := c.run(ctx, s, cmd, cmdTo)
		outs = append(outs, o)
		if !ok {
			return ""
		}
		return o.Stdout
	}

	switch method {
	case "arp":
		for _, h := range parseARP(probe("arp -a")) {
			if ipInNet(h.IP, ipnet) {
				alive[h.IP] = true
			}
		}
	default:
		tcpPorts := defaultProbePorts
		for _, chunk := range chunkStrings(hosts, pingSweepChunk) {
			if method == "tcp" {
				probe(tcpSweepCmd(chunk, tcpPorts))
			} else {
				probe(pingSweepCmd(chunk, os))
			}
		}
	}

	// Enrich with ARP MACs (also the sole source for the arp method).
	arpByIP := map[string]ARPEntry{}
	for _, h := range parseARP(probe("arp -a")) {
		if ipInNet(h.IP, ipnet) {
			alive[h.IP] = true
			arpByIP[h.IP] = h
		}
	}

	// Recover ping-sweep hits from the collected outputs (kept separate so the
	// ARP pass above still runs after the sweep).
	for _, o := range outs {
		for _, h := range parsePingSweep(o.Stdout) {
			if ipInNet(h, ipnet) {
				alive[h] = true
			}
		}
	}

	list := make([]DiscoveredHost, 0, len(alive))
	for ip := range alive {
		dh := DiscoveredHost{Host: ip, Method: method}
		if e, ok := arpByIP[ip]; ok {
			dh.MAC = e.MAC
		}
		list = append(list, dh)
	}
	sort.Slice(list, func(i, j int) bool { return ipLess(list[i].Host, list[j].Host) })

	payload := HostDiscovery{CIDR: ipnet.String(), Method: method, Probed: len(hosts), Truncated: truncated, Hosts: list}
	res, err := core.SuccessResult(fmt.Sprintf("枚举内网主机：网段 %s 探测 %d 台，%d 台存活",
		ipnet.String(), len(hosts), len(list)), payload)
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res.Evidence = core.EvidenceRefs(outs...)
	res.Truncated = truncated
	res.Next = []core.NextStep{{
		Tool: "inet_portscan", Reason: "对存活主机做端口扫描",
		Risk:   core.RiskMedium,
		Params: mustJSON(map[string]any{"session_id": in.SessionID, "hosts": hostList(list), "ports": "21,22,80,135,139,443,445,3389,5985,8080"}),
	}}
	return res, nil
}

var defaultProbePorts = []int{445, 139, 135, 80, 22}

func pingSweepCmd(hosts []string, os string) string {
	joined := strings.Join(hosts, " ")
	if os == "windows" {
		return `for %h in (` + joined + `) do @ping -n 1 -w 1000 %h >nul 2>&1 && @echo UP %h`
	}
	return `for h in ` + joined + `; do ping -c 1 -W 1 "$h" >/dev/null 2>&1 && echo "UP $h"; done`
}

func tcpSweepCmd(hosts []string, ports []int) string {
	portList := joinInts(ports, " ")
	return `for h in ` + strings.Join(hosts, " ") + `; do for p in ` + portList +
		`; do timeout 1 bash -c ">/dev/tcp/$h/$p" 2>/dev/null && echo "UP $h" && break; done; done`
}

// ---- inet_portscan ----

// PortScan is the tool payload.
type PortScan struct {
	ProbedHosts int        `json:"probed_hosts"`
	ProbedPorts int        `json:"probed_ports"`
	Truncated   bool       `json:"truncated"`
	OpenCount   int        `json:"open_count"`
	TotalOpen   int        `json:"total_open"`
	Open        []OpenPort `json:"open"`
}

func (c *Capability) portScan(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		SessionID string   `json:"session_id"`
		Hosts     []string `json:"hosts"`
		CIDR      string   `json:"cidr"`
		Ports     string   `json:"ports"`
		Tool      string   `json:"tool"`
		MaxHosts  int      `json:"max_hosts"`
		MaxPorts  int      `json:"max_ports"`
		PerPortMS int      `json:"per_port_ms"`
		TimeoutMS int      `json:"timeout_ms"`
		Cursor    string   `json:"cursor"`
		PageSize  int      `json:"page_size"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	maxPorts := clampMax(in.MaxPorts, scanDefaultMaxPorts, scanHardMaxPorts)
	ports := parsePortSpec(in.Ports, maxPorts)
	if len(ports) == 0 {
		return core.FailResult(core.InvalidInput("ports 非法或为空")), nil
	}
	portsTruncated := len(ports) == maxPorts

	maxHosts := clampMax(in.MaxHosts, scanDefaultMaxHosts, scanHardMaxHosts)
	hosts, hostsTruncated, e2 := resolveHosts(in.Hosts, in.CIDR, maxHosts)
	if e2 != nil {
		return core.FailResult(e2), nil
	}
	if len(hosts) == 0 {
		return core.FailResult(core.InvalidInput("hosts 或 cidr 至少一个必填")), nil
	}

	to := core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	cmdTo := firstDur(to, maxTimeout)
	tool := strings.ToLower(strings.TrimSpace(in.Tool))
	if tool == "" {
		tool = "tcp"
	}
	perPort := in.PerPortMS
	if perPort <= 0 {
		perPort = 1000
	}

	var (
		mu    sync.Mutex
		outs  []core.Output
		all   []OpenPort
		fails int
	)
	sem := make(chan struct{}, scanConcurrency)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cmd := portScanCmd(host, ports, tool, perPort)
			o, ok := c.run(ctx, s, cmd, cmdTo)
			mu.Lock()
			defer mu.Unlock()
			outs = append(outs, o)
			if !ok {
				fails++
				return
			}
			all = append(all, parseOpenLines(o.Stdout)...)
		}(h)
	}
	wg.Wait()

	all = dedupePorts(all)
	// A scan can open more ports than one envelope should carry, so the list is
	// paged with a cursor (docs §5.5.4).
	start, end, page, perr := core.PageWindow(len(all), in.Cursor, in.PageSize)
	if perr != nil {
		return core.FailResult(perr), nil
	}
	window := all[start:end]
	payload := PortScan{
		ProbedHosts: len(hosts), ProbedPorts: len(ports),
		Truncated: hostsTruncated || portsTruncated,
		OpenCount: len(window), TotalOpen: len(all), Open: window,
	}

	status := core.StatusSuccess
	ok := true
	summary := fmt.Sprintf("扫描 %s 的 %d 个端口，开放 %d 个", hostLabel(hosts), len(ports), len(all))
	if open := openPortList(all); open != "" {
		summary += "：" + open
	}
	if page.HasMore {
		summary += fmt.Sprintf("（本页 %d，用 page.cursor 续取）", len(window))
	}
	if fails == len(hosts) {
		status, ok = core.StatusFailed, false
		summary = fmt.Sprintf("扫描 %s 失败：会话命令均未执行", hostLabel(hosts))
	} else if fails > 0 {
		status, ok = core.StatusPartial, true
		summary += fmt.Sprintf("（%d/%d 台主机命令失败）", fails, len(hosts))
	}
	res, err := core.SuccessResult(summary, payload)
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res.Status, res.OK = status, ok
	if !ok {
		res.Error = core.Unavailable("端口扫描全部失败")
	}
	res.Truncated = payload.Truncated || page.HasMore
	res.Page = page
	res.Evidence = core.EvidenceRefs(outs...)
	return res, nil
}

// hostLabel names the scan targets for a Summary: one host verbatim, or a
// bounded host list.
func hostLabel(hosts []string) string {
	if len(hosts) == 1 {
		return hosts[0]
	}
	shown := hosts
	suffix := ""
	if len(shown) > 3 {
		shown = shown[:3]
		suffix = "…"
	}
	return fmt.Sprintf("%d 台主机(%s%s)", len(hosts), strings.Join(shown, ","), suffix)
}

// openPortList renders the distinct open ports, bounded so the Summary stays
// readable.
func openPortList(open []OpenPort) string {
	seen := map[int]bool{}
	var nums []int
	for _, p := range open {
		if !seen[p.Port] {
			seen[p.Port] = true
			nums = append(nums, p.Port)
		}
	}
	sort.Ints(nums)
	if len(nums) > 10 {
		return joinInts(nums[:10], ",") + ",…"
	}
	return joinInts(nums, ",")
}

func portScanCmd(host string, ports []int, tool string, perPortMS int) string {
	if tool == "nc" {
		return `for p in ` + joinInts(ports, " ") + `; do nc -z -w 1 ` + host +
			` $p 2>/dev/null && echo "OPEN ` + host + ` $p"; done`
	}
	secs := perPortMS / 1000
	if secs < 1 {
		secs = 1
	}
	return `for p in ` + joinInts(ports, " ") + `; do timeout ` + fmt.Sprint(secs) +
		` bash -c ">/dev/tcp/` + host + `/$p" 2>/dev/null && echo "OPEN ` + host + ` $p"; done`
}

func resolveHosts(hosts []string, cidr string, max int) ([]string, bool, *core.Error) {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, h := range hosts {
		add(h)
	}
	truncated := false
	if strings.TrimSpace(cidr) != "" {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || ipnet.IP.To4() == nil {
			return nil, false, core.InvalidInput("cidr 非法: " + cidr)
		}
		expanded, expTrunc := enumerateCIDR(ipnet, max)
		for _, h := range expanded {
			add(h)
		}
		truncated = expTrunc
	}
	if len(out) > max {
		out = out[:max]
		truncated = true
	}
	return out, truncated, nil
}

func dedupePorts(in []OpenPort) []OpenPort {
	seen := map[string]bool{}
	out := make([]OpenPort, 0, len(in))
	for _, p := range in {
		key := p.Host + ":" + fmt.Sprint(p.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return ipLess(out[i].Host, out[j].Host)
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// ---- inet_domain_info ----

// DomainInfo is the tool payload.
type DomainInfo struct {
	Domain string   `json:"domain,omitempty"`
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Trusts []string `json:"trusts,omitempty"`
	DCs    []string `json:"dcs,omitempty"`
}

func (c *Capability) domainInfo(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		SessionID string `json:"session_id"`
		Domain    string `json:"domain"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	to := core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	cmdTo := firstDur(to, defaultTimeout)
	os := c.detectOS(ctx, s, cmdTo)

	out := DomainInfo{Domain: strings.TrimSpace(in.Domain)}
	var outs []core.Output
	run := func(cmd string) string {
		o, ok := c.run(ctx, s, cmd, cmdTo)
		outs = append(outs, o)
		if !ok {
			return ""
		}
		return o.Stdout
	}

	if os == "windows" {
		out.Users = parseUserList(run("net user /domain"))
		out.Groups = parseNetGroup(run("net group /domain"))
		out.Trusts = parseNltest(run("nltest /domain_trusts"))
		if out.Domain != "" {
			out.DCs = parseNltest(run("nltest /dclist:" + out.Domain))
		}
	} else {
		realm := run("realm list")
		ads := run("net ads info")
		for _, line := range parseLogins(realm) {
			if out.Domain == "" && strings.Contains(line, "domain-name:") {
				out.Domain = strings.TrimSpace(strings.TrimPrefix(line, "domain-name:"))
			}
		}
		out.Trusts = parseNltest(ads)
		if out.Domain != "" {
			ldap := run("ldapsearch -x -LLL -H ldap://" + out.Domain + " -b dc=" +
				strings.ReplaceAll(out.Domain, ".", ",dc=") + " sAMAccountName")
			out.Users = parseUserList(ldap)
		}
		if osName(s) == "" && out.Domain == "" && len(out.Trusts) == 0 {
			// Unidentified host OS with no domain evidence: nothing to report.
			return core.FailResult(core.Unavailable("未识别到域环境或域命令不可用")), nil
		}
	}

	summary := fmt.Sprintf("查询域 %s 的信息：用户 %d 个，组 %d 个，信任 %d 条",
		orDash(out.Domain), len(out.Users), len(out.Groups), len(out.Trusts))
	if len(out.DCs) > 0 {
		summary += "，域控 " + joinCapped(out.DCs, 3)
	}
	res, err := core.SuccessResult(summary, out)
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res.Evidence = core.EvidenceRefs(outs...)
	return res, nil
}

// ---- inet_smb_shares ----

// SMBResult is the tool payload.
type SMBResult struct {
	Target string  `json:"target"`
	Count  int     `json:"count"`
	Shares []Share `json:"shares"`
}

func (c *Capability) smbShares(ctx context.Context, call core.Call) (core.Result, error) {
	var in struct {
		SessionID string `json:"session_id"`
		Host      string `json:"host"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return core.FailResult(core.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return core.FailResult(e), nil
	}
	to := core.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	cmdTo := firstDur(to, defaultTimeout)
	target := strings.TrimSpace(in.Host)
	os := c.detectOS(ctx, s, cmdTo)

	var cmds []string
	if target == "" {
		if os == "windows" {
			cmds = []string{"net share"}
		} else {
			cmds = []string{"smbclient -L //127.0.0.1 -N"}
		}
	} else if os == "windows" {
		cmds = []string{"net view \\\\" + target + " /all"}
	} else {
		cmds = []string{"smbclient -L //" + target + " -N"}
	}

	var outs []core.Output
	var shares []Share
	seen := map[string]bool{}
	for _, cmd := range cmds {
		o, ok := c.run(ctx, s, cmd, cmdTo)
		outs = append(outs, o)
		if !ok {
			continue
		}
		for _, sh := range parseNetView(o.Stdout) {
			key := strings.ToLower(sh.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			shares = append(shares, sh)
		}
	}
	sort.Slice(shares, func(i, j int) bool { return shares[i].Name < shares[j].Name })

	displayTarget := target
	if displayTarget == "" {
		displayTarget = "local"
	}
	summary := fmt.Sprintf("枚举 %s 的 SMB 共享：%d 个", displayTarget, len(shares))
	if names := joinCapped(shareNames(shares), 5); names != "" {
		summary += "（" + names + "）"
	}
	res, err := core.SuccessResult(summary, SMBResult{Target: displayTarget, Count: len(shares), Shares: shares})
	if err != nil {
		return core.FailResult(core.UpstreamError(err.Error())), nil
	}
	res.Evidence = core.EvidenceRefs(outs...)
	return res, nil
}

// shareNames lists the discovered share names for a Summary.
func shareNames(shares []Share) []string {
	out := make([]string, 0, len(shares))
	for _, s := range shares {
		out = append(out, s.Name)
	}
	return out
}

// joinCapped joins at most max items, marking the rest with an ellipsis.
func joinCapped(items []string, max int) string {
	if max <= 0 || len(items) == 0 {
		return ""
	}
	if len(items) <= max {
		return strings.Join(items, ",")
	}
	return strings.Join(items[:max], ",") + ",…"
}

// ---- small helpers ----

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func joinInts(in []int, sep string) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, sep)
}

func chunkStrings(in []string, size int) [][]string {
	if size <= 0 {
		size = len(in)
	}
	var out [][]string
	for i := 0; i < len(in); i += size {
		j := i + size
		if j > len(in) {
			j = len(in)
		}
		out = append(out, in[i:j])
	}
	return out
}

func hostList(hosts []DiscoveredHost) []string {
	out := make([]string, len(hosts))
	for i, h := range hosts {
		out[i] = h.Host
	}
	return out
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ipLess orders IPv4 strings numerically, falling back to lexical for
// non-numeric hosts.
func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia != nil && ib != nil {
		return bytesCompare(ia.To4(), ib.To4()) < 0
	}
	return a < b
}

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return len(a) - len(b)
}
