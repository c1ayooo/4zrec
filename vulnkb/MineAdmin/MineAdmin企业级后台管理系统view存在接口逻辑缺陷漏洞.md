# MineAdmin企业级后台管理系统view存在接口逻辑缺陷漏洞

- **系统**：MineAdmin　|　**类型**：逻辑缺陷　|　**CVE**：—
- **指纹**：`body="MineAdmin"`
- **请求**：`POST /prod/system/cache/view HTTP/1.1`
- **关键头**：`Authorization: Bearer (此处替换普通用户token)`　`Content-Type: application/json;charset=UTF-8`　`Content-Length: 27`

**请求体 / payload**
```
POC/EXP：普通用户垂直越权访问MineAdmin:crontab
以下截图对应上面截图中的jwt token证明越权成功。
普通用户jwt token
```
- **预期**：200　|　—