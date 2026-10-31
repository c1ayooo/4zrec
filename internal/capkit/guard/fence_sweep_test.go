package guard

import (
	"os"
	"testing"
)

// Opaque 解释器命令里写死在 heredoc 体中的授权 IP，必须被兜底扫描收进结果
// （2026-10-29 前的实锤误伤：CTF 任务里 socket 直连靶机被一律转人工）。
func TestExtractOpaqueHeredocLiteralIP(t *testing.T) {
	cmd := "cd /tmp && cat > t.py <<'EOF'\nimport socket\ns=socket.create_connection((\"49.51.48.17\",2323),timeout=10)\nEOF\npython3 t.py"
	ft := ExtractFenceTargetsWithDir(cmd, "")
	if !ft.Opaque {
		t.Fatal("解释器 + heredoc 应保持 Opaque（动态目标不可见）")
	}
	if len(ft.IPs) != 1 || ft.IPs[0] != "49.51.48.17" {
		t.Fatalf("heredoc 内的 IPv4 字面量应被兜底扫出: ips=%v domains=%v", ft.IPs, ft.Domains)
	}
}

// 动态目标（无任何字面量）的脚本维持 Opaque 且无目标 —— 围栏据此继续转人工。
func TestExtractOpaqueDynamicTargetStaysEmpty(t *testing.T) {
	cmd := "cat > t.py <<'EOF'\nimport socket, os\ns=socket.create_connection((os.environ[\"HOST\"],80))\nEOF\npython3 t.py"
	ft := ExtractFenceTargetsWithDir(cmd, "")
	if !ft.Opaque {
		t.Fatal("纯动态目标应保持 Opaque")
	}
	if !ft.empty() {
		t.Fatalf("无字面量时不应产出目标: ips=%v domains=%v", ft.IPs, ft.Domains)
	}
}

func TestSweepLiteralTargets(t *testing.T) {
	ft := sweepLiteralTargets("visit https://portal.example.com/api then dial 10.0.0.7:8080, toolchain version 3.11.1")
	if len(ft.IPs) != 1 || ft.IPs[0] != "10.0.0.7" {
		t.Fatalf("IPv4 兜底扫描异常(三段版本号不应误收): %v", ft.IPs)
	}
	if len(ft.Domains) != 1 || ft.Domains[0] != "portal.example.com" {
		t.Fatalf("URL host 兜底扫描异常: %v", ft.Domains)
	}
	// 公共基础设施 IP 不是渗透目标，沿用既有过滤
	ft2 := sweepLiteralTargets("resolver 8.8.8.8, target 49.51.48.17")
	if len(ft2.IPs) != 1 || ft2.IPs[0] != "49.51.48.17" {
		t.Fatalf("公共 DNS 应被过滤: %v", ft2.IPs)
	}
}

// 复合 shell 语句（for/if/$(...) 混排）的切分残片（纯数字、2>&1 残留）不得被
// 当成未知命令转人工——2026-10-29 实锤：planner 的 nmap 等待轮询脚本（纯本地
// ps/sleep/cat）被「未识别的命令 1」挡进审批，agent 停摆 15 分钟。
func TestExtractCompoundLocalScriptNotOpaque(t *testing.T) {
	cmd := "cd /home/u/data/tasks/177\nfor i in $(seq 1 18); do\n  if ! ps -p 2459410 >/dev/null 2>&1; then echo \"nmap finished at iter $i\"; break; fi\n  sleep 10\ndone\necho \"=== nmap_all.txt ===\"\ncat nmap_all.txt 2>/dev\nps -p 2459410 >/dev/null 2>&1 && echo STILL"
	ft := ExtractFenceTargetsWithDir(cmd, "")
	if ft.Opaque {
		t.Fatalf("纯本地复合脚本不应 Opaque: reason=%q ips=%v", ft.Reason, ft.IPs)
	}
}

// 未知命令按「有无网络特征」判定：无特征的长尾本地工具（pgrep/tail 等）
// 按本地放行，段内 IP 字面量照常进结果过范围判定；带特征仍 fail-closed。
func TestExtractUnknownCommandByNetworkIndicator(t *testing.T) {
	local := ExtractFenceTargetsWithDir("pgrep -f telnet_sweep && tail -c 900 sweep2.log", "")
	if local.Opaque {
		t.Fatalf("无网络特征的未知命令不应 Opaque: reason=%q", local.Reason)
	}
	withNet := ExtractFenceTargetsWithDir("mytool --fetch http://10.0.0.9/x", "")
	if !withNet.Opaque {
		t.Fatal("含网络特征的未知命令应保持 Opaque")
	}
}

// 注释行与子 shell 包装残片（第二批复盘）：# 注释段、(cmd; cmd2) 拆段后的
// "(printf" 形态不得再判未知命令。
func TestExtractCommentAndSubshellResidue(t *testing.T) {
	cmd := "# 先清理\n(printf 'prep\\n'; sleep 1)\ncurl -s http://49.51.48.17:8000/answers/"
	ft := ExtractFenceTargetsWithDir(cmd, "")
	if ft.Opaque {
		t.Fatalf("注释/子壳残片不应 Opaque: reason=%q", ft.Reason)
	}
	// URL host 是 IP 时归一到 IPs 列表——两种形态都算照常提取。
	if len(ft.Domains) == 0 && len(ft.IPs) == 0 {
		t.Fatalf("URL 目标应照常提取: %v %v", ft.Domains, ft.IPs)
	}
}

// 解释器脚本体里的字面 IP（元组赋值形态）必须进结果——2026-10-29 第三批实锤：
// telnet_fast.py 的 HOST,PORT = "49.51.48.17",2323 被漏提，纯授权目标又转人工。
func TestExtractInterpreterScriptLiteralIP(t *testing.T) {
	dir := t.TempDir()
	script := dir + "/telnet_fast.py"
	body := "import socket\nHOST, PORT = \"49.51.48.17\", 2323\ns = socket.create_connection((HOST, PORT))\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ft := ExtractFenceTargetsWithDir("python3 telnet_fast.py validate", dir)
	if !ft.Opaque {
		t.Fatal("含网络指示器的脚本应保持 Opaque（动态目标不可见）")
	}
	if len(ft.IPs) != 1 || ft.IPs[0] != "49.51.48.17" {
		t.Fatalf("脚本体内的 IPv4 应被兜底扫出: ips=%v domains=%v", ft.IPs, ft.Domains)
	}
}

// bash 的 stdin-heredoc 脚本（bash <<'EOF' … EOF）：heredoc 体在命令对象分析时被
// 剥离、bash 空参判 Opaque，但字面兜底扫描必须把体内容可见的 IP 收进来，
// 围栏的 scope-pass 才能放行（否则纯授权目标又要转人工）。
func TestExtractBashStdinHeredocLiteralIP(t *testing.T) {
	cmd := "bash <<'EOF'\nimport socket\ns = socket.create_connection((\"49.51.48.17\", 2323))\nEOF\necho done"
	ft := ExtractFenceTargetsWithDir(cmd, "")
	if !ft.Opaque {
		t.Fatal("stdin 脚本应保持 Opaque")
	}
	if len(ft.IPs) != 1 || ft.IPs[0] != "49.51.48.17" {
		t.Fatalf("heredoc 体 IP 应被兜底扫出: ips=%v", ft.IPs)
	}
}
