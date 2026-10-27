// connection_capture.go 凭据自动落库的捕获逻辑:把"刚验证成功的东西"写成
// 一条连接台账。三条路径共用同一套构造:
//
//   - webshell_deploy 投递成功(capkit 工具输出里的 webshell 参数)
//   - session_open 建连成功(ssh/webshell/mysql/postgres/smb/winrm)
//   - http_probe 直接调用已有 shell(URL 查询串里带口令参数与命令参数)
//
// 前两条有显式参数,照抄即可;http_probe 只能靠启发式,所以要求"命令参数值
// 是可验证的探测命令 + 口令参数 + 响应确实是该命令的输出"三条同时成立,避免
// 把普通页面写成台账。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// webshellParams 是一条 WebShell 连接除落点 URL 之外的协议参数。
type webshellParams struct {
	Password  string
	CmdParam  string
	PassParam string
	Method    string
	ShellType string
	Protocol  string
	Proxy     string
}

// shellTypeFromPath 从落点扩展名推断 shell 类型;认不出来就留空,
// 让 capkit 用自己的缺省值而不是猜一个错的。
func shellTypeFromPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	switch strings.ToLower(path.Ext(u.Path)) {
	case ".php", ".php3", ".php4", ".php5", ".phtml":
		return "php"
	case ".asp":
		return "asp"
	case ".aspx", ".ashx", ".asmx":
		return "aspx"
	case ".jsp", ".jspx", ".jspf":
		return "jsp"
	}
	return ""
}

// webshellHostPort 取 URL 的展示字段。台账的 host/port 不参与连接(连接走
// extra.url),但列表和筛选要看着像一条正常的连接。
func webshellHostPort(rawURL string) (string, int, error) {
	u, err := url.Parse(db.NormalizeWebshellURL(rawURL))
	if err != nil || u.Hostname() == "" {
		return "", 0, fmt.Errorf("落点 URL 无效: %q", rawURL)
	}
	port := 80
	if strings.EqualFold(u.Scheme, "https") {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n <= 0 || n > 65535 {
			return "", 0, fmt.Errorf("落点 URL 端口无效: %q", p)
		}
		port = n
	}
	return strings.ToLower(u.Hostname()), port, nil
}

// newWebshellConnection 构造一条 webshell 台账行。extra 的键与
// webshellConfigOf / sessionOpenInputFor 读取的键保持一致。
func newWebshellConnection(rawURL string, p webshellParams) (*db.Connection, error) {
	normalized := db.NormalizeWebshellURL(rawURL)
	host, port, err := webshellHostPort(normalized)
	if err != nil {
		return nil, err
	}
	if p.CmdParam == "" {
		p.CmdParam = "cmd"
	}
	if p.PassParam == "" {
		p.PassParam = "pass"
	}
	if p.Method == "" {
		p.Method = "GET"
	}
	if p.ShellType == "" {
		p.ShellType = shellTypeFromPath(normalized)
	}
	extra := map[string]any{
		"url":        normalized,
		"cmd_param":  p.CmdParam,
		"pass_param": p.PassParam,
		"method":     strings.ToUpper(p.Method),
	}
	if p.ShellType != "" {
		extra["shell_type"] = p.ShellType
	}
	if p.Protocol != "" {
		extra["protocol"] = p.Protocol
	}
	if p.Proxy != "" {
		extra["proxy"] = p.Proxy
	}
	raw, err := json.Marshal(extra)
	if err != nil {
		return nil, err
	}
	return &db.Connection{
		Kind: "webshell", Host: host, Port: port, Secret: p.Password,
		Extra: raw, Status: "alive",
	}, nil
}

// captureWebshell 把一条 WebShell 落进台账。返回给 agent 看的提示(空=未落库)。
func (s *Server) captureWebshell(ctx context.Context, rawURL string, p webshellParams, note string) string {
	c, err := newWebshellConnection(rawURL, p)
	if err != nil {
		return fmt.Sprintf("(WebShell 未写入连接台账: %v)", err)
	}
	c.Note = note
	return s.autoCaptureConnection(ctx, c)
}

// captureCapkitTool 处理 capkit 工具返回后能直接构造出的台账行。
func (s *Server) captureCapkitTool(ctx context.Context, tool string, input json.RawMessage, res capkit.Result) string {
	if !res.OK {
		return ""
	}
	switch tool {
	case "webshell_deploy":
		return s.captureWebshellDeploy(ctx, res)
	case "session_open":
		return s.captureSessionOpen(ctx, input)
	}
	return ""
}

// captureWebshellDeploy 读 webshell_deploy 的 OutputSchema:
// {file_url, webshell:{host, secret, options{cmd_param,pass_param,method,protocol,shell_type}}}
func (s *Server) captureWebshellDeploy(ctx context.Context, res capkit.Result) string {
	var out struct {
		FileURL  string `json:"file_url"`
		Webshell struct {
			Host    string            `json:"host"`
			Secret  string            `json:"secret"`
			Options map[string]string `json:"options"`
		} `json:"webshell"`
	}
	if len(res.Data) == 0 || json.Unmarshal(res.Data, &out) != nil {
		return ""
	}
	target := strings.TrimSpace(out.Webshell.Host)
	if target == "" {
		target = strings.TrimSpace(out.FileURL)
	}
	if target == "" {
		return ""
	}
	opts := out.Webshell.Options
	return s.captureWebshell(ctx, target, webshellParams{
		Password:  out.Webshell.Secret,
		CmdParam:  opts["cmd_param"],
		PassParam: opts["pass_param"],
		Method:    opts["method"],
		ShellType: opts["shell_type"],
		Protocol:  opts["protocol"],
		Proxy:     opts["proxy"],
	}, "webshell_deploy 投递成功")
}

// captureSessionOpen 从 session_open 的入参落库:会话真的建起来了,凭据就是
// 已验证的。cli 是本机会话,目标不是项目资产,不登记。
func (s *Server) captureSessionOpen(ctx context.Context, input json.RawMessage) string {
	var in struct {
		Kind    string            `json:"kind"`
		Host    string            `json:"host"`
		Port    int               `json:"port"`
		User    string            `json:"user"`
		Secret  string            `json:"secret"`
		Domain  string            `json:"domain"`
		Proxy   string            `json:"proxy"`
		Options map[string]string `json:"options"`
	}
	if json.Unmarshal(input, &in) != nil {
		return ""
	}
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	host := strings.TrimSpace(in.Host)
	if kind == "" || kind == "cli" || host == "" || strings.TrimSpace(in.Secret) == "" {
		return ""
	}
	if kind == "webshell" {
		return s.captureWebshell(ctx, host, webshellParams{
			Password:  in.Secret,
			CmdParam:  in.Options["cmd_param"],
			PassParam: in.Options["pass_param"],
			Method:    in.Options["method"],
			ShellType: in.Options["shell_type"],
			Protocol:  in.Options["protocol"],
			Proxy:     in.Proxy,
		}, "session_open 建连成功")
	}
	extra := map[string]any{}
	if dbName := strings.TrimSpace(in.Options["database"]); dbName != "" {
		extra["database"] = dbName
	}
	if sslmode := strings.TrimSpace(in.Options["sslmode"]); sslmode != "" {
		extra["sslmode"] = sslmode
	}
	if domain := strings.TrimSpace(in.Domain); domain != "" {
		extra["domain"] = domain
	}
	if share := strings.TrimSpace(in.Options["share"]); share != "" {
		extra["share"] = share
	}
	var raw json.RawMessage
	if len(extra) > 0 {
		raw, _ = json.Marshal(extra)
	}
	port := in.Port
	if port <= 0 {
		port = db.DefaultConnectionPort(kind)
	}
	return s.autoCaptureConnection(ctx, &db.Connection{
		Kind: kind, Host: host, Port: port, Username: in.User, Secret: in.Secret,
		Extra: raw, Status: "alive", Note: "session_open 建连成功",
	})
}

// ---------- http_probe:识别已有 shell 的调用 ----------

// 命令验证表:只认这些命令,因为它们的输出可以校验。认不出的命令宁可不猜。
var shellCommandHead = map[string]string{
	"id": "id", "whoami": "whoami", "hostname": "hostname", "uname": "uname",
	"pwd": "pwd", "echo": "echo", "ls": "ls", "dir": "dir", "cat": "cat",
	"type": "type", "ipconfig": "ipconfig", "ifconfig": "ifconfig",
}

var uidOutputRe = regexp.MustCompile(`(?m)\buid=\d+`)

// commandOutputMatches 判断响应体是否真的像该命令的输出。这一步是启发式的
// 安全阀:普通页面几乎不可能同时满足"命令参数 + 口令参数 + 命令输出"。
func commandOutputMatches(command, body string) bool {
	body = strings.TrimSpace(body)
	if body == "" || looksLikeHTML(body) {
		return false
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	switch strings.ToLower(fields[0]) {
	case "id":
		return uidOutputRe.MatchString(body)
	case "whoami":
		// Windows 的 whoami 形如 "nt authority\system"(带空格),只要求单行。
		return singleLine(body)
	case "hostname":
		return singleToken(body)
	case "uname":
		low := strings.ToLower(body)
		return singleLine(body) && (strings.Contains(low, "linux") || strings.Contains(low, "darwin") ||
			strings.Contains(low, "bsd") || strings.Contains(low, "gnu"))
	case "pwd":
		return strings.HasPrefix(body, "/")
	case "echo":
		arg := strings.TrimSpace(strings.TrimPrefix(command, fields[0]))
		arg = strings.Trim(arg, `"'`)
		return arg != "" && strings.Contains(body, arg)
	case "ls", "dir", "cat", "type", "ipconfig", "ifconfig":
		return true
	}
	return false
}

func singleLine(s string) bool {
	return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\r\n<>")
}

func singleToken(s string) bool {
	if !singleLine(s) {
		return false
	}
	return !strings.ContainsAny(s, " \t")
}

func looksLikeHTML(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(low, "<!doctype") || strings.HasPrefix(low, "<html") ||
		strings.Contains(low, "<body") || strings.Contains(low, "<head>")
}

// looksLikeShellCommand 判断参数值是不是一条可验证的探测命令。
func looksLikeShellCommand(value string) bool {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return false
	}
	head := strings.ToLower(strings.Trim(fields[0], `"'`))
	_, ok := shellCommandHead[head]
	return ok
}

// looksLikeSecret 判断参数值是否像一个口令:非空、单 token、不是命令、不是
// 纯数字/布尔值/常见页面参数值。
func looksLikeSecret(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < 3 || len(v) > 128 || strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	if looksLikeShellCommand(v) {
		return false
	}
	if _, err := strconv.Atoi(v); err == nil {
		return false
	}
	switch strings.ToLower(v) {
	case "true", "false", "null", "none", "json", "html", "xml", "get", "post",
		"home", "index", "list", "view", "search", "login", "admin", "test":
		return false
	}
	return true
}

// credentialParamNames 是常见口令参数名。命中它们比"值看起来随机"更可靠:
// ?a=shell&pass=zzz123 这种 URL 里,前者是业务参数,后者才是 shell 口令。
var credentialParamNames = map[string]bool{
	"pass": true, "passwd": true, "password": true, "pwd": true, "p": true,
	"k": true, "key": true, "passkey": true, "auth": true, "token": true,
	"shell_pass": true, "cmdpass": true, "secret": true,
}

// secretScore 给候选口令参数打分;-1 表示不像口令。名字像凭据的优先,
// 其次是字母+数字混合、长度足够的值。
func secretScore(name, value string) int {
	if !looksLikeSecret(value) {
		return -1
	}
	score := 0
	if credentialParamNames[strings.ToLower(name)] {
		score += 4
	}
	hasDigit, hasAlpha := false, false
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasAlpha = true
		}
	}
	if hasDigit && hasAlpha {
		score += 2
	} else if hasDigit {
		score++
	}
	if len(value) >= 8 {
		score++
	}
	return score
}

// detectWebshellInvocation 从一次成功的 HTTP 请求里认出"直接调用已有 shell"。
// 返回协议参数与去掉命令/口令参数后的落点 URL。
func detectWebshellInvocation(method, rawURL, body string, status int, respBody string) (string, webshellParams, bool) {
	if status < 200 || status >= 400 {
		return "", webshellParams{}, false
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", webshellParams{}, false
	}
	params := u.Query()
	// POST 表单的 shell:URL 本身没有参数,命令与口令在 body 里。
	if len(params) == 0 && strings.EqualFold(method, "POST") &&
		strings.Contains(body, "=") {
		if form, perr := url.ParseQuery(body); perr == nil {
			params = form
		}
	}
	if len(params) == 0 {
		return "", webshellParams{}, false
	}

	// 排序遍历:map 顺序随机,同分候选必须稳定地选出同一个。
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)

	cmdParam, command := "", ""
	passParam, password := "", ""
	passScore := -1
	for _, name := range names {
		for _, v := range params[name] {
			if cmdParam == "" && looksLikeShellCommand(v) {
				cmdParam, command = name, strings.TrimSpace(v)
				continue
			}
			if score := secretScore(name, v); score > passScore {
				passParam, password, passScore = name, v, score
			}
		}
	}
	if cmdParam == "" || passParam == "" || cmdParam == passParam {
		return "", webshellParams{}, false
	}
	if !commandOutputMatches(command, respBody) {
		return "", webshellParams{}, false
	}

	// 落点 URL 去掉命令与口令参数,其余参数(路由/语言等)保留。
	clean := *u
	q := url.Values{}
	for name, values := range params {
		if name == cmdParam || name == passParam {
			continue
		}
		q[name] = values
	}
	clean.RawQuery = q.Encode()
	clean.Fragment = ""
	target := clean.String()
	if len(q) == 0 {
		target = strings.TrimSuffix(target, "?")
	}
	return target, webshellParams{
		Password:  password,
		CmdParam:  cmdParam,
		PassParam: passParam,
		Method:    method,
		ShellType: shellTypeFromPath(clean.Path),
	}, true
}

// captureProbeWebshell 对一次 http_probe 的结果做启发式识别并落库。
func (s *Server) captureProbeWebshell(ctx context.Context, method, rawURL, body string, status int, respBody string) string {
	target, params, ok := detectWebshellInvocation(method, rawURL, body, status, respBody)
	if !ok {
		return ""
	}
	return s.captureWebshell(ctx, target, params, "http_probe 命中命令回显")
}
