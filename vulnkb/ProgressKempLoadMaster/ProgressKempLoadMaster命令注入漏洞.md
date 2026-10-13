# ProgressKempLoadMaster命令注入漏洞

ProgressKempLoadMaster ｜ SQL注入 ｜ —
- **指纹**：`"LoadMaster"`
- **请求**：`GET /access/set?param=enableapi&value=1 HTTP/1.1`
- **响应特征**：200 ^(?=.*?etc)(?=.*?bin).*?$