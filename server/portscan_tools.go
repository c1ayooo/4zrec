// portscan_tools.go 端口扫描与服务识别工具:portscan/svcid/exposure 三包直接搬自
// 4zreco(免特权 TCP connect + 令牌桶限速 + fingerprintx 协议识别 + fscan 式
// 无凭据暴露探测)。RoE 门控:挂项目上下文时目标必须全部命中项目授权范围,
// 范围外目标硬拒绝(不接受"部分越界");无项目上下文时以人工确认为门。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/db"
	"github.com/c1ayooo/4zrec/intercept"
	"github.com/c1ayooo/4zrec/recon/exposure"
	"github.com/c1ayooo/4zrec/recon/portscan"
	"github.com/c1ayooo/4zrec/recon/svcid"
	actool "github.com/c1ayooo/4zrec/tools"
)

// roeProjectID 解析当前调用的项目上下文:显式参数 > 任务归属项目 > 会话归属项目。
// 与围栏 resolveProject 同语义(guard 包私有,这里为 RoE 门控复刻)。
func (s *Server) roeProjectID(ctx context.Context, explicit int64) int64 {
	if explicit > 0 {
		return explicit
	}
	if taskIDStr, _ := intercept.TaskInfoFromContext(ctx); taskIDStr != "" {
		if id, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64); err == nil && id > 0 {
			if pid, err := s.m.pg.TaskProjectID(id); err == nil && pid > 0 {
				return pid
			}
		}
	}
	if convID := intercept.ConvIDFromContext(ctx); convID > 0 {
		if pid, err := s.m.pg.ConvProjectID(convID); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

// expandScanTargets 展开 IP/CIDR 目标列表;总量超上限直接报错(防误填 /0)。
func expandScanTargets(targets []string, maxIPs int) ([]string, error) {
	if maxIPs <= 0 {
		maxIPs = 4096
	}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !strings.Contains(t, "/") {
			if net.ParseIP(t) == nil {
				return nil, fmt.Errorf("目标 %q 不是合法 IP/CIDR", t)
			}
			out = append(out, t)
			continue
		}
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			return nil, fmt.Errorf("目标 %q 不是合法 CIDR: %v", t, err)
		}
		var cnt int
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			cnt++
			if cnt > maxIPs {
				return nil, fmt.Errorf("目标 %q 展开超过 %d 个 IP 上限,请拆分或缩小网段", t, maxIPs)
			}
			out = append(out, ip.String())
			if cnt == 1 && ip.To4() != nil {
				// IPv4 网络地址本身也计入;广播地址在 Contains 判定内自然包含
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有可扫描的目标")
	}
	if len(out) > maxIPs {
		return nil, fmt.Errorf("目标总数 %d 超过 %d 上限", len(out), maxIPs)
	}
	return out, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// toolPortScan 端口扫描 → 服务识别(fingerprintx) → 暴露面探测(fscan 式,可选)。
func (s *Server) toolPortScan() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "port_scan",
		Description: "端口扫描与服务识别(主动探测,免特权 TCP connect):内置 top100/web 端口集或自定义端口," +
			"令牌桶限速(默认 500 连接/秒,无需 root);开放端口经 fingerprintx 做协议识别(http/ssh/redis/mysql…)," +
			"可选对识别出的中间件跑无凭据暴露面探测(fscan 式:Redis 未授权/ES 开放/FTP 匿名等)。" +
			"挂项目上下文时目标必须全部命中项目授权范围,范围外目标直接拒绝。结果入库(IP 资产带开放端口,http 端口建服务资产)。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"targets":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "IP 或 CIDR 列表"},
				"ports":      map[string]any{"type": "string", "description": "端口集:top100(默认)/web/自定义逗号列表或范围段(如 22,80,3306 或 8000-8100)"},
				"rate":       map[string]any{"type": "integer", "description": "每秒新建连接上限(默认 500)"},
				"timeout_ms": map[string]any{"type": "integer", "description": "单连接超时毫秒(默认 2000)"},
				"svcid":      map[string]any{"type": "boolean", "description": "开放端口做协议识别(默认 true;大网段可关)"},
				"expose":     map[string]any{"type": "boolean", "description": "对识别出的中间件跑无凭据暴露面探测(默认 false)"},
				"project_id": map[string]any{"type": "integer", "description": "导入目标项目(可选;挂项目任务自动取上下文)"},
			},
			"required": []string{"targets"},
		},
		Permissions: func(_ context.Context, input json.RawMessage, _ actool.Context) actool.Decision {
			// 主动探测:必须过操作者的目(与 subdomain_brute/Bash 同语义)。
			var in struct {
				Targets []string `json:"targets"`
				Ports   string   `json:"ports"`
			}
			_ = json.Unmarshal(input, &in)
			ports := in.Ports
			if ports == "" {
				ports = "top100"
			}
			return actool.AskUser(fmt.Sprintf("端口扫描(主动探测)目标: %s | 端口: %s",
				strings.Join(in.Targets, ", "), ports))
		},
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Targets   []string `json:"targets"`
				Ports     string   `json:"ports"`
				Rate      int      `json:"rate"`
				TimeoutMs int      `json:"timeout_ms"`
				SvcID     *bool    `json:"svcid"`
				Expose    bool     `json:"expose"`
				ProjectID int64    `json:"project_id"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if len(in.Targets) == 0 {
				return actool.Errorf("targets 不能为空"), nil
			}

			// ---- RoE 门控:挂项目上下文时,范围外目标硬拒绝。----
			projectID := s.roeProjectID(ctx, in.ProjectID)
			ips, err := expandScanTargets(in.Targets, 4096)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if projectID > 0 {
				rules, rerr := s.m.pg.ProjectScopeRules(projectID)
				if rerr != nil {
					return actool.Errorf("RoE 校验失败(读取项目范围): " + rerr.Error()), nil
				}
				var allowed, denied []string
				for _, ip := range ips {
					if _, ok := db.MatchProjectScope(rules, "", ip); ok {
						allowed = append(allowed, ip)
					} else {
						denied = append(denied, ip)
					}
				}
				if len(denied) > 0 {
					sort.Strings(denied)
					capd := denied
					if len(capd) > 20 {
						capd = capd[:20]
					}
					return actool.Errorf(fmt.Sprintf(
						"【RoE 拒绝】%d 个目标不在项目 %d 授权范围内(示例: %s)。请只扫描授权内目标。",
						len(denied), projectID, strings.Join(capd, ", "))), nil
				}
				ips = allowed
			}

			// ---- 端口扫描 ----
			set, custom := "top100", ""
			switch in.Ports {
			case "", "top100", "web":
				set = in.Ports
			default: // 逗号列表/范围段(如 22,80,3306 或 8000-8100)
				custom = in.Ports
			}
			ports := portscan.ResolvePorts(set, custom)
			if len(ports) == 0 {
				return actool.Errorf("端口集无效: " + in.Ports), nil
			}
			timeout := time.Duration(in.TimeoutMs) * time.Millisecond
			results := portscan.Scan(ctx, ips, portscan.Options{
				Ports: ports, RatePerSec: in.Rate, Timeout: timeout,
			})
			if len(results) == 0 {
				return actool.Text(fmt.Sprintf("扫描 %d 个 IP × %d 端口:无开放端口", len(ips), len(ports))), nil
			}
			byIP := map[string][]portscan.Result{}
			for _, r := range results {
				byIP[r.IP] = append(byIP[r.IP], r)
			}

			// ---- 服务识别(默认开) ----
			svcOn := in.SvcID == nil || *in.SvcID
			svcByIPPort := map[string]svcid.Service{}
			if svcOn {
				for ip, rs := range byIP {
					open := make([]int, 0, len(rs))
					for _, r := range rs {
						open = append(open, r.Port)
					}
					for _, sv := range svcid.Scan(ctx, ip, open, svcid.Options{Timeout: 3 * time.Second}) {
						svcByIPPort[fmt.Sprintf("%s:%d", ip, sv.Port)] = sv
					}
				}
			}

			// ---- 暴露面探测(可选,fscan 式无凭据) ----
			var expTargets []exposure.Target
			if in.Expose {
				for key, sv := range svcByIPPort {
					if !exposure.Supported(sv.Protocol) {
						continue
					}
					host, portStr, _ := net.SplitHostPort(key)
					p, _ := strconv.Atoi(portStr)
					expTargets = append(expTargets, exposure.Target{Host: host, Port: p, Service: sv.Protocol})
				}
			}
			var expFindings []exposure.Result
			if len(expTargets) > 0 {
				expFindings = exposure.Scan(ctx, expTargets, exposure.Options{Timeout: 3 * time.Second})
			}

			// ---- 入库:IP 资产带开放端口;http/https 端口补建服务资产 ----
			var imported int
			as := s.m.Assets()
			for ip, rs := range byIP {
				open := make([]db.PortService, 0, len(rs))
				for _, r := range rs {
					svc := r.Service
					if sv, ok := svcByIPPort[fmt.Sprintf("%s:%d", ip, r.Port)]; ok && sv.Protocol != "" && sv.Protocol != "unknown" {
						svc = sv.Protocol
					}
					open = append(open, db.PortService{Port: r.Port, Service: svc})
				}
				id, err := as.UpsertIP(db.UpsertIPReq{IP: ip, OpenPorts: open})
				if err != nil {
					continue
				}
				imported++
				if projectID > 0 {
					_, _ = as.StampDiscoveredAsset(id, projectID)
				}
				for _, r := range rs {
					sv, ok := svcByIPPort[fmt.Sprintf("%s:%d", ip, r.Port)]
					if !ok || (sv.Protocol != "http" && sv.Protocol != "https") {
						continue
					}
					scheme := sv.Protocol
					if sid, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{
						URL: fmt.Sprintf("%s://%s:%d", scheme, ip, r.Port), TaskID: 0,
					}); err == nil && projectID > 0 {
						_, _ = as.StampDiscoveredAsset(sid, projectID)
					}
				}
			}

			// ---- 输出 ----
			var b strings.Builder
			fmt.Fprintf(&b, "扫描完成:%d IP × %d 端口,开放 %d 处(涉及 %d 个 IP),入库 IP 资产 %d 个",
				len(ips), len(ports), len(results), len(byIP), imported)
			if !svcOn {
				b.WriteString("(未做协议识别)")
			}
			b.WriteString("\n")
			for ip, rs := range byIP {
				sort.Slice(rs, func(i, j int) bool { return rs[i].Port < rs[j].Port })
				parts := make([]string, 0, len(rs))
				for _, r := range rs {
					label := strconv.Itoa(r.Port)
					if sv, ok := svcByIPPort[fmt.Sprintf("%s:%d", ip, r.Port)]; ok && sv.Protocol != "" && sv.Protocol != "unknown" {
						label += "/" + sv.Protocol
						if sv.Version != "" {
							label += " " + sv.Version
						}
					}
					parts = append(parts, label)
				}
				fmt.Fprintf(&b, "- %s: %s\n", ip, strings.Join(parts, " "))
			}
			if len(expFindings) > 0 {
				b.WriteString("暴露面探测:\n")
				for _, f := range expFindings {
					fmt.Fprintf(&b, "- %s:%d %s — %s\n", f.Host, f.Port, f.Service, f.Finding)
				}
			}
			if projectID > 0 {
				fmt.Fprintf(&b, "(范围校验:项目 %d,全部目标在授权内)\n", projectID)
			}
			return actool.Text(b.String()), nil
		},
	})
}
